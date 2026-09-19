import { motion, AnimatePresence } from 'framer-motion';
import { X, ExternalLink, ShieldAlert, ShieldCheck, Info } from 'lucide-react';
import type { AlertEvent } from './types';

interface Props {
  alert: AlertEvent | null;
  onClose: () => void;
}

const SEVERITY_CONFIG = {
  CRITICAL: {
    label: 'Critical',
    bg: 'bg-red-500/15',
    border: 'border-[var(--danger)]',
    text: 'text-[var(--danger)]',
    icon: <ShieldAlert size={16} />,
  },
  WARN: {
    label: 'Warning',
    bg: 'bg-amber-500/15',
    border: 'border-amber-500/40',
    text: 'text-[var(--warn)]',
    icon: <ShieldCheck size={16} />,
  },
  INFO: {
    label: 'Info',
    bg: 'bg-sky-500/10',
    border: 'border-sky-500/30',
    text: 'text-[var(--accent)]',
    icon: <Info size={16} />,
  },
};

const EXPLORER_TX = 'https://explorer.arc.io/tx/';

function Row({ label, value, mono = false }: { label: string; value: string | number | boolean | undefined; mono?: boolean }) {
  const display = value === undefined || value === '' ? '—' : String(value);
  return (
    <div className="flex items-start justify-between gap-4 py-2 border-b border-[var(--border)] last:border-0">
      <span className="text-xs text-[var(--subtle)] uppercase tracking-wide shrink-0" style={{ letterSpacing: '0.07em' }}>{label}</span>
      <span className={`text-xs text-[var(--ink-2)] text-right break-all ${mono ? 'mono' : ''}`}>{display}</span>
    </div>
  );
}

export function AlertDetail({ alert, onClose }: Props) {
  return (
    <AnimatePresence>
      {alert && (
        <>
          {/* Backdrop */}
          <motion.div
            key="backdrop"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm"
            onClick={onClose}
          />
          {/* Sheet */}
          <motion.div
            key="sheet"
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', stiffness: 340, damping: 32 }}
            className="fixed right-0 top-0 bottom-0 z-50 w-full max-w-sm bg-[#0e1e33] border-l border-[var(--border)] flex flex-col overflow-hidden"
          >
            {/* Header */}
            {(() => {
              const cfg = SEVERITY_CONFIG[alert.severity];
              return (
                <div className={`px-5 py-4 border-b border-[var(--border)] ${cfg.bg} flex items-start justify-between gap-3`}>
                  <div className="flex items-center gap-2">
                    <span className={cfg.text}>{cfg.icon}</span>
                    <div>
                      <p className={`display text-sm font-semibold ${cfg.text}`}>{cfg.label}</p>
                      <p className="text-xs text-[var(--subtle)] mt-0.5">{alert.eventName}</p>
                    </div>
                  </div>
                  <button
                    onClick={onClose}
                    className="text-[var(--subtle)] hover:text-[var(--ink)] p-1 rounded-md hover:bg-[var(--surface)] transition-colors mt-0.5"
                    aria-label="Close detail"
                  >
                    <X size={16} />
                  </button>
                </div>
              );
            })()}

            {/* Body */}
            <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
              {/* Message */}
              <div className="rounded-lg bg-[var(--surface-muted)] px-4 py-3">
                <p className="text-sm text-[var(--ink-2)] text-pretty">{alert.message}</p>
              </div>

              {/* Core fields */}
              <div>
                <Row label="Block"    value={alert.blockNumber} mono />
                <Row label="Time"     value={new Date(alert.timestamp).toLocaleTimeString()} />
                <Row label="Contract" value={alert.contract.length > 20 ? `${alert.contract.slice(0,10)}…${alert.contract.slice(-8)}` : alert.contract} mono />
              </div>

              {/* Tx Hash */}
              {alert.txHash && (
                <div>
                  <p className="text-[10px] text-[var(--subtle)] uppercase tracking-wide mb-1" style={{ letterSpacing: '0.07em' }}>Transaction</p>
                  <a
                    href={`${EXPLORER_TX}${alert.txHash}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="inline-flex items-center gap-1.5 mono text-xs text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors break-all"
                  >
                    {alert.txHash.slice(0, 18)}…{alert.txHash.slice(-8)}
                    <ExternalLink size={10} className="shrink-0" />
                  </a>
                </div>
              )}

              {/* Event Data */}
              {Object.keys(alert.data).length > 0 && (
                <div>
                  <p className="text-[10px] text-[var(--subtle)] uppercase tracking-wide mb-2" style={{ letterSpacing: '0.07em' }}>Event Data</p>
                  <div className="rounded-lg bg-[var(--surface-muted)] px-4 py-1">
                    {Object.entries(alert.data).map(([k, v]) => (
                      <Row key={k} label={k} value={v} mono={k === 'from' || k === 'to' || k === 'subject' || k === 'caller' || k === 'operator'} />
                    ))}
                  </div>
                </div>
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
