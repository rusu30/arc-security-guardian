/**
 * Mock alert stream for the dashboard preview.
 * In production, replace this with a real SSE connection to /api/guardian/alerts/stream.
 * This generates synthetic Guardian events that mirror the exact AlertRecord shape
 * the real telemetry service emits.
 */
import { useState, useEffect, useCallback } from 'react';
import type { AlertEvent, StatsSnapshot } from './types';

const CONTRACTS = {
  SecurityEventEmitter: import.meta.env.VITE_GUARDIAN_EMITTER as string ?? '0xe39b...d189',
  SecurityRegistry:     import.meta.env.VITE_GUARDIAN_REGISTRY as string ?? '0x9976...7096',
  TransactionValidationHook: import.meta.env.VITE_GUARDIAN_HOOK as string ?? '0x73f7...e036',
  TwoFactorAuthGuard:   import.meta.env.VITE_GUARDIAN_TFA_GUARD as string ?? '0x0ae2...e40',
};

const AGENT_ADDRS = [
  '0xA1b2C3d4E5f6A7b8C9d0E1F2a3B4c5D6e7F8a9B0',
  '0x3F9aB2c3D4e5F6a7B8C9d0E1f2A3b4C5D6E7f8A9',
  '0xDeAdBeEf1234567890AbCdEf1234567890AbCdEf',
  '0x1111111111111111111111111111111111111111',
  '0x5B12Ce46C7194aD57d143bC22847224047b1Ef42',
];
const REASONS = ['VelocityAmountExceeded', 'AddressBlocked', 'VelocityCallsExceeded', 'InvalidTFASignature'];
const TIER_CHANGES: Array<[string, string]> = [
  ['CLEAN', 'WATCH'], ['WATCH', 'BLOCKED'], ['BLOCKED', 'CLEAN'],
  ['UNKNOWN', 'VERIFIED_AGENT'], ['WATCH', 'CLEAN'],
];

let _counter = 1000;
function nextId() { return `alert-${Date.now()}-${_counter++}`; }
function pick<T>(arr: T[]): T { return arr[Math.floor(Math.random() * arr.length)]; }
function short(addr: string) {
  if (addr.length < 12) return addr;
  return `${addr.slice(0, 6)}…${addr.slice(-4)}`;
}
function fakeHash() {
  const hex = '0123456789abcdef';
  return '0x' + Array.from({ length: 64 }, () => hex[Math.floor(Math.random() * 16)]).join('');
}
function fakeUsdc() { return (Math.random() * 9800 + 200).toFixed(2); }

function randomEvent(): AlertEvent {
  const roll = Math.random();
  const from = pick(AGENT_ADDRS);
  const to = pick(AGENT_ADDRS.filter(a => a !== from));
  const amount = fakeUsdc();
  const txHash = fakeHash();
  const blockNumber = String(19_800_000 + Math.floor(Math.random() * 5000));
  const ts = Date.now();

  if (roll < 0.05) {
    // CRITICAL — EmergencyPause
    return {
      id: nextId(), severity: 'CRITICAL', eventName: 'EmergencyPause',
      contract: CONTRACTS.SecurityEventEmitter, txHash, blockNumber, timestamp: ts,
      data: { operator: short(from), target: short(to), reason: 'Anomaly spike detected' },
      message: `EMERGENCY PAUSE on ${short(to)} by ${short(from)}: Anomaly spike detected`,
    };
  }
  if (roll < 0.18) {
    // WARN — VelocityBreach
    const limit = (Math.random() * 5000 + 1000).toFixed(2);
    return {
      id: nextId(), severity: 'WARN', eventName: 'VelocityBreach',
      contract: CONTRACTS.SecurityEventEmitter, txHash, blockNumber, timestamp: ts,
      data: { subject: short(from), amountUsed: amount, limit },
      message: `Velocity breach: ${short(from)} used ${amount} USDC (limit ${limit})`,
    };
  }
  if (roll < 0.30) {
    // WARN — Validation Failed
    const reason = pick(REASONS);
    return {
      id: nextId(), severity: 'WARN', eventName: 'SecurityValidation',
      contract: CONTRACTS.TransactionValidationHook, txHash, blockNumber, timestamp: ts,
      data: { from: short(from), to: short(to), amount, ok: false, reason },
      message: `Validation FAILED (${reason}): ${short(from)} → ${short(to)} ${amount} USDC`,
    };
  }
  if (roll < 0.40) {
    // INFO — RiskTierChanged
    const [oldTier, newTier] = pick(TIER_CHANGES);
    return {
      id: nextId(), severity: newTier === 'BLOCKED' ? 'WARN' : 'INFO', eventName: 'RiskTierChanged',
      contract: CONTRACTS.SecurityRegistry, txHash, blockNumber, timestamp: ts,
      data: { subject: short(from), oldTier, newTier, operator: short(to) },
      message: `Risk tier for ${short(from)}: ${oldTier} → ${newTier} (by ${short(to)})`,
    };
  }
  if (roll < 0.50) {
    // INFO — TFA challenge consumed
    return {
      id: nextId(), severity: 'INFO', eventName: 'TFAChallengeConsumed',
      contract: CONTRACTS.TwoFactorAuthGuard, txHash, blockNumber, timestamp: ts,
      data: { caller: short(from), to: short(to), amount, nonce: String(Math.floor(Math.random() * 999)) },
      message: `2FA challenge consumed: ${short(from)} → ${short(to)} ${amount} USDC`,
    };
  }
  // INFO — Validation Passed
  return {
    id: nextId(), severity: 'INFO', eventName: 'SecurityValidation',
    contract: CONTRACTS.TransactionValidationHook, txHash, blockNumber, timestamp: ts,
    data: { from: short(from), to: short(to), amount, ok: true },
    message: `Validation PASSED: ${short(from)} → ${short(to)} ${amount} USDC`,
  };
}

function buildStats(alerts: AlertEvent[]): StatsSnapshot {
  return {
    totalAlerts: alerts.length,
    criticalCount: alerts.filter(a => a.severity === 'CRITICAL').length,
    warnCount: alerts.filter(a => a.severity === 'WARN').length,
    infoCount: alerts.filter(a => a.severity === 'INFO').length,
    velocityBreaches: alerts.filter(a => a.eventName === 'VelocityBreach').length,
    blockedTxns: alerts.filter(a => a.data.reason === 'AddressBlocked' || a.data.reason === 'VelocityAmountExceeded').length,
    tfaChallenges: alerts.filter(a => a.eventName === 'TFAChallengeConsumed').length,
    lastBlock: Math.max(0, ...alerts.map(a => parseInt(a.blockNumber, 10) || 0)),
  };
}

const INITIAL_ALERTS: AlertEvent[] = Array.from({ length: 24 }, (_, i) => ({
  ...randomEvent(),
  timestamp: Date.now() - (24 - i) * 12_000,
}));

export function useMockAlerts() {
  const [alerts, setAlerts] = useState<AlertEvent[]>(INITIAL_ALERTS);
  const [stats, setStats] = useState<StatsSnapshot>(buildStats(INITIAL_ALERTS));
  const [selected, setSelected] = useState<AlertEvent | null>(null);
  const [isPaused, setIsPaused] = useState(false);
  const [filter, setFilter] = useState<AlertSeverity | 'ALL'>('ALL');

  const addAlert = useCallback((alert: AlertEvent) => {
    setAlerts(prev => {
      const next = [alert, ...prev].slice(0, 200);
      setStats(buildStats(next));
      return next;
    });
  }, []);

  // Simulate live stream: 1 event every ~3-8 seconds
  useEffect(() => {
    if (isPaused) return;
    const jitter = () => 3000 + Math.random() * 5000;
    let tid: ReturnType<typeof setTimeout>;
    const schedule = () => {
      tid = setTimeout(() => {
        addAlert(randomEvent());
        schedule();
      }, jitter());
    };
    schedule();
    return () => clearTimeout(tid);
  }, [isPaused, addAlert]);

  const filtered = filter === 'ALL' ? alerts : alerts.filter(a => a.severity === filter);

  return { alerts: filtered, allAlerts: alerts, stats, selected, setSelected, isPaused, setIsPaused, filter, setFilter };
}

type AlertSeverity = 'INFO' | 'WARN' | 'CRITICAL';
