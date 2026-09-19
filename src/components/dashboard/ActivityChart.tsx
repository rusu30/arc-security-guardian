/**
 * ActivityChart — mini sparkline of events over the last 60s, bucketed into 12 bars.
 * Uses pure SVG/CSS — no external chart library needed.
 */
import { useMemo } from 'react';
import type { AlertEvent } from './types';

interface Props {
  alerts: AlertEvent[];
  nowMs?: number;
}

const BUCKETS = 20;
const WINDOW_MS = 60_000;

export function ActivityChart({ alerts, nowMs }: Props) {
  const bars = useMemo(() => {
    const now = nowMs ?? 0;
    const bucketSize = WINDOW_MS / BUCKETS;
    const counts = new Array<number>(BUCKETS).fill(0);
    const criticals = new Array<number>(BUCKETS).fill(0);

    for (const a of alerts) {
      const age = now - a.timestamp;
      if (age < 0 || age >= WINDOW_MS) continue;
      const idx = Math.floor(age / bucketSize);
      const bucket = BUCKETS - 1 - idx;
      if (bucket >= 0 && bucket < BUCKETS) {
        counts[bucket]++;
        if (a.severity === 'CRITICAL' || a.severity === 'WARN') criticals[bucket]++;
      }
    }

    const max = Math.max(1, ...counts);
    return counts.map((c, i) => ({
      total: c,
      hot: criticals[i],
      heightPct: (c / max) * 100,
      hotPct: (criticals[i] / max) * 100,
    }));
  }, [alerts, nowMs]);

  const totalLast60 = bars.reduce((s, b) => s + b.total, 0);
  const hotLast60   = bars.reduce((s, b) => s + b.hot, 0);

  return (
    <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] backdrop-blur-sm px-5 py-4">
      <div className="flex items-center justify-between mb-3">
        <h2 className="display font-semibold text-sm text-[var(--ink-2)]" style={{ letterSpacing: '0.06em', textTransform: 'uppercase' }}>
          Activity (last 60s)
        </h2>
        <div className="flex items-center gap-3">
          <span className="mono tabular-nums text-xs text-[var(--success)]">{totalLast60} events</span>
          {hotLast60 > 0 && (
            <span className="mono tabular-nums text-xs text-[var(--warn)]">{hotLast60} threats</span>
          )}
        </div>
      </div>

      {/* Bar chart */}
      <div className="flex items-end gap-0.5 h-14">
        {bars.map((b, i) => (
          <div key={i} className="flex-1 flex flex-col justify-end h-full gap-0">
            {/* Hot portion */}
            <div
              className="w-full rounded-t-sm transition-all duration-300"
              style={{
                height: `${b.hotPct}%`,
                backgroundColor: b.hot > 0 ? 'var(--danger)' : 'transparent',
                opacity: 0.8,
              }}
            />
            {/* Total portion */}
            <div
              className="w-full rounded-t-sm transition-all duration-300"
              style={{
                height: `${Math.max(0, b.heightPct - b.hotPct)}%`,
                backgroundColor: 'var(--accent)',
                opacity: 0.4,
              }}
            />
          </div>
        ))}
      </div>

      <div className="flex justify-between mt-1">
        <span className="text-[9px] text-[var(--subtle)]">60s ago</span>
        <span className="text-[9px] text-[var(--subtle)]">now</span>
      </div>
    </div>
  );
}
