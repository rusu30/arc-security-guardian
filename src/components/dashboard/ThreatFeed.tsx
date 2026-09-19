import { useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ShieldAlert, ShieldCheck, Info, Pause, Play } from 'lucide-react';
import type { AlertEvent, AlertSeverity } from './types';

interface Props {
  alerts: AlertEvent[];
  selected: AlertEvent | null;
  onSelect: (alert: AlertEvent) => void;
  isPaused: boolean;
  onTogglePause: () => void;
  filter: AlertSeverity | 'ALL';
  onFilterChange: (f: AlertSeverity | 'ALL') => void;
  totalCount: number;
}

const SEV = {
  CRITICAL: { icon: <ShieldAlert size={13} />, color: 'text-[var(--danger)]', dot: 'bg-[var(--danger)]', badge: 'bg-red-500/15 text-[var(--danger)]' },
  WARN:     { icon: <ShieldCheck size={13} />, color: 'text-[var(--warn)]',   dot: 'bg-[var(--warn)]',   badge: 'bg-amber-500/15 text-[var(--warn)]' },
  INFO:     { icon: <Info size={13} />,        color: 'text-[var(--accent)]', dot: 'bg-[var(--accent)]', badge: 'bg-sky-500/10 text-[var(--accent)]' },
};

const FILTERS: Array<{ key: AlertSeverity | 'ALL'; label: string }> = [
  { key: 'ALL',      label: 'All' },
  { key: 'CRITICAL', label: 'Critical' },
  { key: 'WARN',     label: 'Warn' },
  { key: 'INFO',     label: 'Info' },
];

function timeAgo(ts: number) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 5)  return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

export function ThreatFeed({ alerts, selected, onSelect, isPaused, onTogglePause, filter, onFilterChange, totalCount }: Props) {
  const topRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to top when new alert arrives and not paused
  useEffect(() => {
    if (!isPaused && topRef.current) {
      topRef.current.scrollTop = 0;
    }
  }, [alerts.length, isPaused]);

  return (
    <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] backdrop-blur-sm flex flex-col overflow-hidden h-full">
      {/* Header */}
      <div className="px-5 py-4 border-b border-[var(--border)] flex items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-2">
          <h2 className="display font-semibold text-sm text-[var(--ink-2)]" style={{ letterSpacing: '0.06em', textTransform: 'uppercase' }}>
            Threat Feed
          </h2>
          <span className="mono text-[10px] text-[var(--subtle)] bg-[var(--surface-muted)] px-1.5 py-0.5 rounded">
            {totalCount}
          </span>
        </div>
        <button
          onClick={onTogglePause}
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${isPaused ? 'bg-[var(--accent)]/20 text-[var(--accent)]' : 'text-[var(--subtle)] hover:text-[var(--ink)] hover:bg-[var(--surface-strong)]'}`}
        >
          {isPaused ? <Play size={11} /> : <Pause size={11} />}
          {isPaused ? 'Resume' : 'Pause'}
        </button>
      </div>

      {/* Filter tabs */}
      <div className="px-4 py-2 flex items-center gap-1 border-b border-[var(--border)] shrink-0 overflow-x-auto">
        {FILTERS.map(f => (
          <button
            key={f.key}
            onClick={() => onFilterChange(f.key)}
            className={`px-3 py-1 rounded-lg text-xs font-medium whitespace-nowrap transition-colors ${
              filter === f.key
                ? 'bg-[var(--surface-strong)] text-[var(--ink)]'
                : 'text-[var(--subtle)] hover:text-[var(--ink-2)] hover:bg-[var(--surface)]'
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      {/* Feed list */}
      <div ref={topRef} className="flex-1 overflow-y-auto">
        {alerts.length === 0 && (
          <div className="flex flex-col items-center justify-center h-32 text-[var(--subtle)] text-sm">
            <ShieldCheck size={20} className="mb-2 text-[var(--success)]" />
            No events in this filter
          </div>
        )}
        <AnimatePresence initial={false}>
          {alerts.map((alert) => {
            const cfg = SEV[alert.severity];
            const isSelected = selected?.id === alert.id;
            return (
              <motion.button
                key={alert.id}
                layout
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.22 }}
                onClick={() => onSelect(alert)}
                className={`w-full text-left px-4 py-3 border-b border-[var(--border)] flex items-start gap-3 transition-colors ${
                  isSelected ? 'bg-[var(--surface-strong)]' : 'hover:bg-[var(--surface-muted)]/40'
                }`}
              >
                {/* Severity dot */}
                <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${cfg.dot} ${alert.severity === 'CRITICAL' ? 'animate-pulse' : ''}`} />

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`inline-flex items-center gap-0.5 text-[10px] font-semibold ${cfg.color}`}>
                      {cfg.icon}
                      {alert.eventName}
                    </span>
                    <span className="mono text-[10px] text-[var(--subtle)] tabular-nums">{timeAgo(alert.timestamp)}</span>
                  </div>
                  <p className="text-xs text-[var(--muted)] mt-0.5 text-pretty leading-relaxed line-clamp-2">{alert.message}</p>
                  <p className="mono text-[9px] text-[var(--subtle)] mt-1 truncate">blk {alert.blockNumber}</p>
                </div>

                {/* Severity badge */}
                <span className={`shrink-0 text-[9px] font-semibold px-1.5 py-0.5 rounded uppercase tracking-wide ${cfg.badge}`} style={{ letterSpacing: '0.07em' }}>
                  {alert.severity}
                </span>
              </motion.button>
            );
          })}
        </AnimatePresence>
      </div>
    </div>
  );
}
