import { motion } from 'framer-motion';
import { ExternalLink, Lock, RefreshCw } from 'lucide-react';

interface ContractRow {
  name: string;
  address: string;
  role: string;
  mutable: boolean;
  chain: string;
}

const CONTRACTS: ContractRow[] = [
  {
    name: 'SecurityEventEmitter',
    address: import.meta.env.VITE_GUARDIAN_EMITTER as string ?? '',
    role: 'Canonical on-chain event bus',
    mutable: false,
    chain: 'Arc Testnet',
  },
  {
    name: 'TwoFactorAuthGuard',
    address: import.meta.env.VITE_GUARDIAN_TFA_GUARD as string ?? '',
    role: 'EIP-712 2FA challenge verifier',
    mutable: false,
    chain: 'Arc Testnet',
  },
  {
    name: 'SecurityRegistry',
    address: import.meta.env.VITE_GUARDIAN_REGISTRY as string ?? '',
    role: 'UUPS risk registry (upgradeable)',
    mutable: true,
    chain: 'Arc Testnet',
  },
  {
    name: 'TransactionValidationHook',
    address: import.meta.env.VITE_GUARDIAN_HOOK as string ?? '',
    role: 'Pre-execution transaction gate',
    mutable: false,
    chain: 'Arc Testnet',
  },
];

const EXPLORER_BASE = 'https://explorer.arc.io/address/';

function shortAddr(addr: string) {
  if (!addr || addr.length < 12) return addr ?? '—';
  return `${addr.slice(0, 8)}…${addr.slice(-6)}`;
}

export function ContractMap() {
  return (
    <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] backdrop-blur-sm overflow-hidden">
      <div className="px-5 py-4 border-b border-[var(--border)] flex items-center justify-between">
        <h2 className="display font-semibold text-sm text-[var(--ink-2)]" style={{ letterSpacing: '0.06em', textTransform: 'uppercase' }}>
          Deployed Contracts
        </h2>
        <span className="text-xs text-[var(--subtle)] mono">Arc Testnet · 5042002</span>
      </div>
      <div className="divide-y divide-[var(--border)]">
        {CONTRACTS.map((c, i) => (
          <motion.div
            key={c.name}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3, delay: i * 0.07 }}
            className="px-5 py-3.5 flex items-center gap-3 hover:bg-[var(--surface-strong)] transition-colors"
          >
            <div className="shrink-0 text-[var(--subtle)]">
              {c.mutable ? (
                <RefreshCw size={14} className="text-[var(--warn)]" />
              ) : (
                <Lock size={14} className="text-[var(--success)]" />
              )}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="display text-sm font-semibold text-[var(--ink)]">{c.name}</span>
                <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium tracking-wide uppercase ${c.mutable ? 'bg-amber-500/15 text-[var(--warn)]' : 'bg-emerald-500/15 text-[var(--success)]'}`}>
                  {c.mutable ? 'upgradeable' : 'immutable'}
                </span>
              </div>
              <p className="text-xs text-[var(--subtle)] mt-0.5 text-pretty">{c.role}</p>
            </div>
            <div className="shrink-0 text-right">
              {c.address ? (
                <a
                  href={`${EXPLORER_BASE}${c.address}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 mono text-xs text-[var(--accent)] hover:text-[var(--accent-hover)] transition-colors"
                >
                  {shortAddr(c.address)}
                  <ExternalLink size={10} />
                </a>
              ) : (
                <span className="mono text-xs text-[var(--subtle)]">not set</span>
              )}
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
