export type AlertSeverity = 'INFO' | 'WARN' | 'CRITICAL';
export type RiskTier = 'UNKNOWN' | 'CLEAN' | 'WATCH' | 'BLOCKED' | 'VERIFIED_AGENT';

export interface AlertEvent {
  id: string;
  severity: AlertSeverity;
  eventName: string;
  contract: string;
  txHash: string;
  blockNumber: string;
  timestamp: number;
  data: Record<string, string | number | boolean | undefined>;
  message: string;
}

export interface ContractInfo {
  name: string;
  address: string;
  role: string;
  mutable: boolean;
  alertCount: number;
}

export interface StatsSnapshot {
  totalAlerts: number;
  criticalCount: number;
  warnCount: number;
  infoCount: number;
  velocityBreaches: number;
  blockedTxns: number;
  tfaChallenges: number;
  lastBlock: number;
}
