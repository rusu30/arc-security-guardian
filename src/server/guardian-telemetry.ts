/**
 * Arc Security Guardian — Real-Time Event Telemetry Service
 *
 * Listens to on-chain security events from the four deployed Guardian contracts
 * over a WebSocket RPC connection to Arc Testnet. Parses and normalises each
 * event into an AlertRecord and forwards it to all registered in-process listeners.
 *
 * Usage (from a server route or startup file):
 *
 *   import { GuardianTelemetry } from '@/server/guardian-telemetry';
 *   const telemetry = new GuardianTelemetry();
 *   telemetry.start();
 *   telemetry.on('alert', (alert) => console.log(alert));
 *
 * Environment variables:
 *   VITE_GUARDIAN_EMITTER         SecurityEventEmitter address
 *   VITE_GUARDIAN_REGISTRY        SecurityRegistry address
 *   VITE_GUARDIAN_HOOK            TransactionValidationHook address
 *   VITE_GUARDIAN_TFA_GUARD       TwoFactorAuthGuard address
 *   RPC_PROXY_BASE_URL            Arc Studio RPC proxy base URL
 *   RPC_PROXY_TOKEN               Arc Studio RPC proxy token
 *   RPC_PROXY_CHAINS              Comma-separated chain IDs the proxy covers
 */

import { EventEmitter } from 'node:events';
import { createPublicClient, webSocket, parseAbiItem, type Log } from 'viem';
import { arcTestnet } from 'viem/chains';

// ─── Safe log accessors ───────────────────────────────────────────────────────
// viem's Log<bigint, number, false> doesn't carry typed args/address on the base
// type, but watchEvent returns logs whose args are populated. We extract them
// safely through unknown rather than casting to any.

function logAddress(log: Log): string {
  return (log as unknown as { address?: string }).address ?? '';
}

function logArgs(log: Log): Record<string, unknown> {
  return ((log as unknown as { args?: Record<string, unknown> }).args) ?? {};
}

function safeStr(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined;
}

function safeBigint(v: unknown): bigint | undefined {
  return typeof v === 'bigint' ? v : typeof v === 'number' ? BigInt(v) : undefined;
}

function safeNum(v: unknown): number {
  return typeof v === 'number' ? v : typeof v === 'bigint' ? Number(v) : 0;
}

function safeBool(v: unknown): boolean {
  return v === true;
}

// ─── Contract Addresses (read from env — never hardcoded) ────────────────────

function requireEnv(key: string): `0x${string}` {
  const v = process.env[key];
  if (!v) throw new Error(`[Guardian Telemetry] Missing env var: ${key}`);
  return v as `0x${string}`;
}

function getContracts() {
  return {
    SecurityEventEmitter: requireEnv('VITE_GUARDIAN_EMITTER'),
    SecurityRegistry: requireEnv('VITE_GUARDIAN_REGISTRY'),
    TransactionValidationHook: requireEnv('VITE_GUARDIAN_HOOK'),
    TwoFactorAuthGuard: requireEnv('VITE_GUARDIAN_TFA_GUARD'),
  };
}

/** Resolves the best available WebSocket RPC URL for Arc Testnet (chain 5042002). */
function resolveWsRpc(): string {
  const proxyBase = process.env.RPC_PROXY_BASE_URL;
  const proxyToken = process.env.RPC_PROXY_TOKEN;
  const proxyChains = process.env.RPC_PROXY_CHAINS ?? '';

  const arcTestnetId = 5042002;
  const proxied = proxyChains.split(',').map((s) => parseInt(s.trim(), 10));

  if (proxyBase && proxyToken && proxyChains && proxyChains.length > 0 && proxied.includes(arcTestnetId)) {
    // Use the Studio-provisioned RPC proxy (preferred — authenticated, no public rate limits)
    const wsBase = proxyBase.replace(/^https?:\/\//, (m) =>
      m.startsWith('https') ? 'wss://' : 'ws://',
    );
    return `${wsBase}/api/rpc/${arcTestnetId}?_rpc_token=${proxyToken}`;
  }

  // Fall back to the public Arc Testnet WebSocket endpoint
  // Arc Testnet public RPC: read from the onchain-facts registry at runtime
  return arcTestnet.rpcUrls.default.webSocket?.[0] ?? arcTestnet.rpcUrls.default.http[0].replace('https', 'wss');
}

// ─── Alert Types ─────────────────────────────────────────────────────────────

export type AlertSeverity = 'INFO' | 'WARN' | 'CRITICAL';

export interface AlertRecord {
  id: string;
  severity: AlertSeverity;
  eventName: string;
  contract: string;
  txHash: string;
  blockNumber: bigint;
  timestamp: number;    // unix ms
  data: Record<string, unknown>;
  message: string;
}

// ─── ABI fragments ────────────────────────────────────────────────────────────

const EVENTS = {
  SecurityValidation: parseAbiItem(
    'event SecurityValidation(address indexed from, address indexed to, uint256 amount, bool ok, string reason)',
  ),
  RiskTierChanged: parseAbiItem(
    'event RiskTierChanged(address indexed subject, uint8 oldTier, uint8 newTier, address indexed operator)',
  ),
  RiskFlagChanged: parseAbiItem(
    'event RiskFlagChanged(address indexed subject, uint8 flagBit, bool value, address indexed operator)',
  ),
  VelocityBreach: parseAbiItem(
    'event VelocityBreach(address indexed subject, uint256 windowStart, uint256 amountUsed, uint256 limit)',
  ),
  EmergencyPause: parseAbiItem(
    'event EmergencyPause(address indexed operator, address indexed target, string reason)',
  ),
  TFAChallengeConsumed: parseAbiItem(
    'event TFAChallengeConsumed(address indexed caller, address indexed to, uint256 amount, uint256 nonce)',
  ),
  ChallengeConsumed: parseAbiItem(
    'event ChallengeConsumed(address indexed caller, address indexed to, uint256 amount, uint256 nonce, uint256 deadline)',
  ),
} as const;

const RISK_TIER_NAMES: Record<number, string> = {
  0: 'UNKNOWN', 1: 'CLEAN', 2: 'WATCH', 3: 'BLOCKED', 4: 'VERIFIED_AGENT',
};
function tierName(n: number) { return RISK_TIER_NAMES[n] ?? `TIER_${n}`; }

// ─── Main telemetry class ─────────────────────────────────────────────────────

export class GuardianTelemetry extends EventEmitter {
  private client: ReturnType<typeof createPublicClient> | null = null;
  private unwatchers: Array<() => void> = [];
  private alertCounter = 0;
  private running = false;

  start(): void {
    if (this.running) return;
    this.running = true;

    const wsUrl = resolveWsRpc();
    this.client = createPublicClient({
      chain: arcTestnet,
      transport: webSocket(wsUrl, { reconnect: true }),
    });

    this._subscribeAll();
    console.log('[Guardian Telemetry] Started. Listening to Arc Testnet events.');
  }

  stop(): void {
    for (const unwatch of this.unwatchers) {
      try { unwatch(); } catch { /* ignore */ }
    }
    this.unwatchers = [];
    this.running = false;
    console.log('[Guardian Telemetry] Stopped.');
  }

  private _subscribeAll(): void {
    const c = this.client!;
    const contracts = getContracts();

    this.unwatchers.push(
      c.watchEvent({
        address: contracts.SecurityEventEmitter,
        event: EVENTS.SecurityValidation,
        onLogs: (logs) => logs.forEach((l) => this._handleSecurityValidation(l)),
      }),
      c.watchEvent({
        address: contracts.SecurityEventEmitter,
        event: EVENTS.RiskTierChanged,
        onLogs: (logs) => logs.forEach((l) => this._handleRiskTierChanged(l)),
      }),
      c.watchEvent({
        address: contracts.SecurityEventEmitter,
        event: EVENTS.RiskFlagChanged,
        onLogs: (logs) => logs.forEach((l) => this._handleRiskFlagChanged(l)),
      }),
      c.watchEvent({
        address: contracts.SecurityEventEmitter,
        event: EVENTS.VelocityBreach,
        onLogs: (logs) => logs.forEach((l) => this._handleVelocityBreach(l)),
      }),
      c.watchEvent({
        address: contracts.SecurityEventEmitter,
        event: EVENTS.EmergencyPause,
        onLogs: (logs) => logs.forEach((l) => this._handleEmergencyPause(l)),
      }),
      c.watchEvent({
        address: contracts.SecurityEventEmitter,
        event: EVENTS.TFAChallengeConsumed,
        onLogs: (logs) => logs.forEach((l) => this._handleTFAConsumed(l)),
      }),
      c.watchEvent({
        address: contracts.TwoFactorAuthGuard,
        event: EVENTS.ChallengeConsumed,
        onLogs: (logs) => logs.forEach((l) => this._handleChallengeConsumed(l)),
      }),
    );
  }

  private _makeId() { return `alert-${Date.now()}-${++this.alertCounter}`; }

  private _emit(alert: AlertRecord): void {
    this.emit('alert', alert);
    const icon = alert.severity === 'CRITICAL' ? '🔴' : alert.severity === 'WARN' ? '🟡' : '🟢';
    console.log(`${icon} [Guardian] ${alert.severity} ${alert.eventName}: ${alert.message}`);
  }

  private _handleSecurityValidation(log: Log): void {
    const a = logArgs(log);
    const from = safeStr(a.from); const to = safeStr(a.to);
    const amount = safeBigint(a.amount); const ok = safeBool(a.ok);
    const reason = safeStr(a.reason) ?? '';
    this._emit({
      id: this._makeId(), severity: ok ? 'INFO' : 'WARN',
      eventName: 'SecurityValidation', contract: logAddress(log),
      txHash: log.transactionHash ?? '', blockNumber: log.blockNumber ?? 0n,
      timestamp: Date.now(),
      data: { from, to, amount: amount?.toString(), ok, reason },
      message: ok
        ? `Validation PASSED: ${_short(from)} → ${_short(to)} ${_usdc(amount)} USDC`
        : `Validation FAILED (${reason}): ${_short(from)} → ${_short(to)} ${_usdc(amount)} USDC`,
    });
  }

  private _handleRiskTierChanged(log: Log): void {
    const a = logArgs(log);
    const subject = safeStr(a.subject); const operator = safeStr(a.operator);
    const oldTier = safeNum(a.oldTier); const newTier = safeNum(a.newTier);
    this._emit({
      id: this._makeId(), severity: newTier === 3 ? 'WARN' : 'INFO',
      eventName: 'RiskTierChanged', contract: logAddress(log),
      txHash: log.transactionHash ?? '', blockNumber: log.blockNumber ?? 0n,
      timestamp: Date.now(),
      data: { subject, oldTier: tierName(oldTier), newTier: tierName(newTier), operator },
      message: `Risk tier for ${_short(subject)}: ${tierName(oldTier)} → ${tierName(newTier)} (by ${_short(operator)})`,
    });
  }

  private _handleRiskFlagChanged(log: Log): void {
    const a = logArgs(log);
    const subject = safeStr(a.subject); const operator = safeStr(a.operator);
    const flagBit = safeNum(a.flagBit); const value = safeBool(a.value);
    this._emit({
      id: this._makeId(), severity: 'INFO',
      eventName: 'RiskFlagChanged', contract: logAddress(log),
      txHash: log.transactionHash ?? '', blockNumber: log.blockNumber ?? 0n,
      timestamp: Date.now(),
      data: { subject, flagBit, value, operator },
      message: `Flag bit ${flagBit} ${value ? 'SET' : 'CLEARED'} on ${_short(subject)} by ${_short(operator)}`,
    });
  }

  private _handleVelocityBreach(log: Log): void {
    const a = logArgs(log);
    const subject = safeStr(a.subject);
    const windowStart = safeBigint(a.windowStart);
    const amountUsed = safeBigint(a.amountUsed);
    const limit = safeBigint(a.limit);
    this._emit({
      id: this._makeId(), severity: 'WARN',
      eventName: 'VelocityBreach', contract: logAddress(log),
      txHash: log.transactionHash ?? '', blockNumber: log.blockNumber ?? 0n,
      timestamp: Date.now(),
      data: { subject, windowStart: windowStart?.toString(), amountUsed: amountUsed?.toString(), limit: limit?.toString() },
      message: `Velocity breach: ${_short(subject)} used ${_usdc(amountUsed)} USDC (limit ${_usdc(limit)})`,
    });
  }

  private _handleEmergencyPause(log: Log): void {
    const a = logArgs(log);
    const operator = safeStr(a.operator); const target = safeStr(a.target);
    const reason = safeStr(a.reason) ?? '';
    this._emit({
      id: this._makeId(), severity: 'CRITICAL',
      eventName: 'EmergencyPause', contract: logAddress(log),
      txHash: log.transactionHash ?? '', blockNumber: log.blockNumber ?? 0n,
      timestamp: Date.now(),
      data: { operator, target, reason },
      message: `EMERGENCY PAUSE on ${_short(target)} by ${_short(operator)}: ${reason}`,
    });
  }

  private _handleTFAConsumed(log: Log): void {
    const a = logArgs(log);
    const caller = safeStr(a.caller); const to = safeStr(a.to);
    const amount = safeBigint(a.amount); const nonce = safeBigint(a.nonce);
    this._emit({
      id: this._makeId(), severity: 'INFO',
      eventName: 'TFAChallengeConsumed', contract: logAddress(log),
      txHash: log.transactionHash ?? '', blockNumber: log.blockNumber ?? 0n,
      timestamp: Date.now(),
      data: { caller, to, amount: amount?.toString(), nonce: nonce?.toString() },
      message: `2FA challenge consumed: ${_short(caller)} → ${_short(to)} ${_usdc(amount)} USDC (nonce ${nonce?.toString()})`,
    });
  }

  private _handleChallengeConsumed(log: Log): void {
    const a = logArgs(log);
    const caller = safeStr(a.caller); const to = safeStr(a.to);
    const amount = safeBigint(a.amount); const nonce = safeBigint(a.nonce);
    const deadline = safeBigint(a.deadline);
    this._emit({
      id: this._makeId(), severity: 'INFO',
      eventName: 'ChallengeConsumed', contract: logAddress(log),
      txHash: log.transactionHash ?? '', blockNumber: log.blockNumber ?? 0n,
      timestamp: Date.now(),
      data: { caller, to, amount: amount?.toString(), nonce: nonce?.toString(), deadline: deadline?.toString() },
      message: `TFA challenge on-chain: ${_short(caller)} → ${_short(to)} ${_usdc(amount)} USDC`,
    });
  }
}

export const guardianTelemetry = new GuardianTelemetry();

function _short(addr: string | undefined): string {
  if (!addr || addr.length < 10) return addr ?? '?';
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}

function _usdc(raw: bigint | undefined): string {
  if (raw === undefined || raw === null) return '?';
  return (Number(raw) / 1_000_000).toFixed(2);
}
