import { useState, useEffect } from 'react';
import { Header } from '@/components/dashboard/Header';
import { StatsBar } from '@/components/dashboard/StatsBar';
import { ThreatFeed } from '@/components/dashboard/ThreatFeed';
import { ContractMap } from '@/components/dashboard/ContractMap';
import { AlertDetail } from '@/components/dashboard/AlertDetail';
import { ActivityChart } from '@/components/dashboard/ActivityChart';
import { useMockAlerts } from '@/components/dashboard/useMockAlerts';

export default function App() {
  // Tick every 2s so the activity chart buckets refresh without calling Date.now() during render.
  // Initialise with a lazy-evaluated Date.now() so the first render already has a real timestamp.
  const [nowMs, setNowMs] = useState<number>(() => Date.now());

  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 2000);
    return () => clearInterval(id);
  }, []);

  const {
    alerts,
    allAlerts,
    stats,
    selected,
    setSelected,
    isPaused,
    setIsPaused,
    filter,
    setFilter,
  } = useMockAlerts();

  return (
    <div className="min-h-dvh" style={{ background: 'var(--bg-gradient)', backgroundAttachment: 'fixed' }}>
      <Header isLive={!isPaused} lastBlock={stats.lastBlock} />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 py-6 space-y-5">

        {/* Stats row */}
        <StatsBar stats={stats} />

        {/* Activity sparkline */}
        <ActivityChart alerts={allAlerts} nowMs={nowMs} />

        {/* Two-column: feed (left) + contract map (right) */}
        <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">

          {/* Threat feed — takes 3/5 width on desktop */}
          <div className="lg:col-span-3" style={{ minHeight: '540px' }}>
            <ThreatFeed
              alerts={alerts}
              selected={selected}
              onSelect={setSelected}
              isPaused={isPaused}
              onTogglePause={() => setIsPaused(p => !p)}
              filter={filter}
              onFilterChange={setFilter}
              totalCount={allAlerts.length}
            />
          </div>

          {/* Right column — contract map + 2FA summary */}
          <div className="lg:col-span-2 space-y-4">
            <ContractMap />

            {/* 2FA Status panel */}
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] backdrop-blur-sm px-5 py-4 space-y-3">
              <h2 className="display font-semibold text-sm text-[var(--ink-2)]" style={{ letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                2FA Guard
              </h2>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-[var(--subtle)]">Mode</span>
                  <span className="mono text-[var(--ink-2)]">EIP-712 typed-data</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[var(--subtle)]">Max challenge lifetime</span>
                  <span className="mono text-[var(--ink-2)]">300s</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[var(--subtle)]">Replay protection</span>
                  <span className="text-[var(--success)] font-medium">usedChallenges map</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[var(--subtle)]">Challenges consumed</span>
                  <span className="mono tabular-nums text-[var(--ink-2)]">{stats.tfaChallenges}</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[var(--subtle)]">Binding</span>
                  <span className="text-[var(--success)] font-medium">msg.sender == caller</span>
                </div>
              </div>
            </div>

            {/* Velocity config panel */}
            <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)] backdrop-blur-sm px-5 py-4 space-y-3">
              <h2 className="display font-semibold text-sm text-[var(--ink-2)]" style={{ letterSpacing: '0.06em', textTransform: 'uppercase' }}>
                Velocity Config (Default)
              </h2>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between items-center">
                  <span className="text-[var(--subtle)]">Window</span>
                  <span className="mono text-[var(--ink-2)]">3600s (1h)</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[var(--subtle)]">USDC limit / window</span>
                  <span className="mono tabular-nums text-[var(--ink-2)]">1,000 USDC</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[var(--subtle)]">Call limit / window</span>
                  <span className="mono tabular-nums text-[var(--ink-2)]">100 calls</span>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-[var(--subtle)]">Breaches this session</span>
                  <span className={`mono tabular-nums font-medium ${stats.velocityBreaches > 0 ? 'text-[var(--warn)]' : 'text-[var(--success)]'}`}>
                    {stats.velocityBreaches}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Alert detail sheet */}
      <AlertDetail alert={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
