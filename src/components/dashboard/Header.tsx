import { Shield, Wifi, WifiOff } from 'lucide-react';

interface Props {
  isLive: boolean;
  lastBlock: number;
}

export function Header({ isLive, lastBlock }: Props) {
  return (
    <header className="flex items-center justify-between px-6 py-4 border-b border-[var(--border)] bg-[var(--surface)] backdrop-blur-sm sticky top-0 z-30">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-lg bg-[var(--accent)]/15 flex items-center justify-center">
          <Shield size={16} className="text-[var(--accent)]" />
        </div>
        <div>
          <h1 className="display font-semibold text-sm text-[var(--ink)] leading-none" style={{ letterSpacing: '-0.01em' }}>
            Arc Security Guardian
          </h1>
          <p className="text-[10px] text-[var(--subtle)] mt-0.5">Risk Management Middleware · Arc Testnet</p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        {lastBlock > 0 && (
          <div className="hidden sm:flex items-center gap-1.5">
            <span className="text-[10px] text-[var(--subtle)] uppercase tracking-wide" style={{ letterSpacing: '0.07em' }}>Block</span>
            <span className="mono tabular-nums text-xs text-[var(--ink-2)]">{lastBlock.toLocaleString()}</span>
          </div>
        )}
        <div className={`flex items-center gap-1.5 text-xs font-medium ${isLive ? 'text-[var(--success)]' : 'text-[var(--subtle)]'}`}>
          {isLive ? (
            <>
              <span className="w-1.5 h-1.5 rounded-full bg-[var(--success)] animate-pulse" />
              <Wifi size={12} />
              <span className="hidden sm:inline">Live</span>
            </>
          ) : (
            <>
              <WifiOff size={12} />
              <span className="hidden sm:inline">Paused</span>
            </>
          )}
        </div>
      </div>
    </header>
  );
}
