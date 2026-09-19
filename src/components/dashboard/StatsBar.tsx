import { motion } from 'framer-motion';
import { ShieldCheck, ShieldAlert, Zap, Lock, KeyRound, Activity } from 'lucide-react';
import type { StatsSnapshot } from './types';

interface Props {
  stats: StatsSnapshot;
}

interface StatCardProps {
  label: string;
  value: number | string;
  icon: React.ReactNode;
  accent?: 'danger' | 'warn' | 'success' | 'default';
  index: number;
}

function StatCard({ label, value, icon, accent = 'default', index }: StatCardProps) {
  const accentColor = {
    danger: 'text-[var(--danger)]',
    warn: 'text-[var(--warn)]',
    success: 'text-[var(--success)]',
    default: 'text-[var(--accent)]',
  }[accent];

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: index * 0.06 }}
      className="rounded-xl border border-[var(--border)] bg-[var(--surface)] px-4 py-3 flex items-center gap-3 backdrop-blur-sm"
    >
      <div className={`shrink-0 ${accentColor}`}>{icon}</div>
      <div className="min-w-0">
        <p className="display tabular-nums text-xl font-semibold text-[var(--ink)] leading-none">{value}</p>
        <p className="text-xs text-[var(--subtle)] mt-0.5 tracking-wide uppercase" style={{ letterSpacing: '0.07em' }}>{label}</p>
      </div>
    </motion.div>
  );
}

export function StatsBar({ stats }: Props) {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
      <StatCard index={0} label="Total Events" value={stats.totalAlerts}    icon={<Activity size={18} />} />
      <StatCard index={1} label="Critical"     value={stats.criticalCount}  icon={<ShieldAlert size={18} />} accent="danger" />
      <StatCard index={2} label="Warnings"     value={stats.warnCount}      icon={<ShieldCheck size={18} />} accent="warn" />
      <StatCard index={3} label="Vel. Breaches" value={stats.velocityBreaches} icon={<Zap size={18} />} accent="warn" />
      <StatCard index={4} label="Blocked Txns" value={stats.blockedTxns}    icon={<Lock size={18} />} accent="danger" />
      <StatCard index={5} label="2FA Consumed" value={stats.tfaChallenges}  icon={<KeyRound size={18} />} accent="success" />
    </div>
  );
}
