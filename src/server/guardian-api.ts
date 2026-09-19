/**
 * Arc Security Guardian — HTTP API + SSE Alert Stream
 *
 * Exposes three endpoints for integrating Guardian telemetry into your app:
 *
 *   GET /api/guardian/status          — health check + deployed contract addresses
 *   GET /api/guardian/alerts/stream   — Server-Sent Events stream of live alerts
 *   GET /api/guardian/alerts/recent   — last N alerts from the in-memory ring buffer
 *
 * Mount with mountGuardianApi(app) on any Hono/Express-compatible framework.
 *
 * Query params for /recent:
 *   limit=50            max alerts to return (capped at 200)
 *   severity=WARN       filter by INFO | WARN | CRITICAL
 */

import { guardianTelemetry, type AlertRecord } from '@/server/guardian-telemetry';

// ─── In-memory ring buffer (last 200 alerts) ──────────────────────────────────

const MAX_RECENT = 200;
const recentAlerts: AlertRecord[] = [];
const sseClients = new Set<(alert: AlertRecord) => void>();

guardianTelemetry.on('alert', (alert: AlertRecord) => {
  if (recentAlerts.length >= MAX_RECENT) recentAlerts.shift();
  recentAlerts.push(alert);
  for (const cb of sseClients) {
    try { cb(alert); } catch { sseClients.delete(cb); }
  }
});

// ─── Route handlers ───────────────────────────────────────────────────────────

export function handleStatus(_req: Request): Response {
  return json({
    ok: true,
    chain: 'Arc Testnet',
    chainId: 5042002,
    contracts: {
      SecurityEventEmitter: process.env.VITE_GUARDIAN_EMITTER,
      SecurityRegistry: process.env.VITE_GUARDIAN_REGISTRY,
      TransactionValidationHook: process.env.VITE_GUARDIAN_HOOK,
      TwoFactorAuthGuard: process.env.VITE_GUARDIAN_TFA_GUARD,
    },
    recentAlertCount: recentAlerts.length,
    connectedStreams: sseClients.size,
  });
}

export function handleRecentAlerts(req: Request): Response {
  const url = new URL(req.url);
  const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '50', 10), MAX_RECENT);
  const severity = url.searchParams.get('severity')?.toUpperCase();
  let alerts = recentAlerts.slice(-limit).reverse();
  if (severity) alerts = alerts.filter((a) => a.severity === severity);
  return json({ ok: true, count: alerts.length, alerts });
}

export function handleAlertStream(_req: Request): Response {
  const encoder = new TextEncoder();
  let push: ((a: AlertRecord) => void) | null = null;
  let heartbeat: ReturnType<typeof setInterval> | null = null;
  let ctrl: ReadableStreamDefaultController<Uint8Array> | null = null;

  const stream = new ReadableStream<Uint8Array>({
    start(c) {
      ctrl = c;
      // Replay last 10 alerts on connect
      for (const a of recentAlerts.slice(-10)) {
        c.enqueue(encoder.encode(`data: ${JSON.stringify(a)}\n\n`));
      }
      push = (a) => {
        try { c.enqueue(encoder.encode(`data: ${JSON.stringify(a)}\n\n`)); }
        catch { cleanup(); }
      };
      sseClients.add(push);
      heartbeat = setInterval(() => {
        try { c.enqueue(encoder.encode(': heartbeat\n\n')); }
        catch { cleanup(); }
      }, 30_000);
    },
    cancel() { cleanup(); },
  });

  function cleanup() {
    if (push) sseClients.delete(push);
    if (heartbeat) clearInterval(heartbeat);
    try { ctrl?.close(); } catch { /* already closed */ }
  }

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'Access-Control-Allow-Origin': '*',
    },
  });
}

/** Mounts all Guardian API routes and starts the telemetry listener. */
export function mountGuardianApi(app: {
  get: (path: string, handler: (req: Request) => Response | Promise<Response>) => void;
}): void {
  guardianTelemetry.start();
  app.get('/api/guardian/status', handleStatus);
  app.get('/api/guardian/alerts/recent', handleRecentAlerts);
  app.get('/api/guardian/alerts/stream', handleAlertStream);
}

function json(data: unknown): Response {
  return new Response(JSON.stringify(data), { headers: { 'Content-Type': 'application/json' } });
}
