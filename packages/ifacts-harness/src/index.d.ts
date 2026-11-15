export declare const IFACTS_REPORT_FORMAT: 'ifacts-report/1.0';
export declare const COFAY_BOUNDARY_ERROR_CODE: 'COFAY_OUT_OF_SCOPE_USE_COFACTS';

export type IfactsLevelStatus =
  | 'passed'
  | 'failed'
  | 'blocked_by_previous_level'
  | 'not_requested'
  | 'not_applicable_cofay'
  | 'deferred_phase_4_behavioral';

export type IfayReadyTier = 'None' | 'Bronze' | 'Silver' | 'Gold';

export interface IfactsCheckResult {
  id: string;
  component?: string;
  protocol?: string;
  vectorSource?: 'sibling_repo' | 'builtin_fallback';
  vectorCount?: number;
  passed: boolean;
  detail: string;
}

export interface IfactsLevelReport {
  level: 'L1' | 'L2' | 'L3';
  status: IfactsLevelStatus;
  passedCount: number;
  failedCount: number;
  checks: IfactsCheckResult[];
}

export interface AuditChainEntry {
  index: number;
  timestamp: string;
  stage: string;
  payload: Record<string, unknown>;
  prevHash: string;
  entryHash: string;
}

export interface IfayReadyCapabilities {
  firstPersonTracer?: boolean;
  simulatedOperation?: boolean;
  capProtocol?: boolean;
  dtpProtocol?: boolean;
  credentialDelegation?: boolean;
  sspProtocol?: boolean;
  cfsIntegration?: boolean;
}

export interface IfactsReport {
  reportFormat: 'ifacts-report/1.0';
  generatedAt: string;
  subject: string;
  overallStatus: 'passed' | 'failed' | 'rejected_out_of_scope';
  errorCode?: string;
  message?: string;
  resolvedPhase: string | null;
  levels: {
    L1: IfactsLevelReport;
    L2: IfactsLevelReport;
    L3: IfactsLevelReport;
    L4: { level: 'L4'; status: IfactsLevelStatus; note: string };
  };
  ifayReady: {
    tier: IfayReadyTier;
    eligibleTiers: IfayReadyTier[];
    rationale: string;
  };
  summary?: {
    totalChecksExecuted: number;
    totalPassed: number;
    totalFailed: number;
  };
}

export declare function createAuditHashChain(): {
  append(stage: string, payload: Record<string, unknown>, timestamp?: string): AuditChainEntry;
  entries(): AuditChainEntry[];
};

export declare function verifyAuditHashChain(
  entries: AuditChainEntry[],
): { valid: boolean; brokenIndex?: number; reason?: string; length?: number; headHash?: string };

export declare function runL1Conformance(options?: {
  manifest?: Record<string, unknown>;
  egoManifestOverride?: Record<string, unknown>;
  tamperEgoSignature?: boolean;
}): IfactsLevelReport;

export declare function runL2Conformance(options?: {
  disableSiblingRepoLookup?: boolean;
  injectL2FailureForTest?: boolean;
}): IfactsLevelReport;

export declare function runL3Conformance(): IfactsLevelReport & { auditTrail: AuditChainEntry[] };

export declare function evaluateIfayReadyTier(
  capabilities?: IfayReadyCapabilities,
  levelStatuses?: { L1?: IfactsLevelStatus; L2?: IfactsLevelStatus; L3?: IfactsLevelStatus },
): {
  tier: IfayReadyTier;
  eligibleTiers: IfayReadyTier[];
  rationale: string;
};

export declare function runIfactsSuite(options?: {
  subjectId?: string;
  entityType?: 'ifay' | 'cofay';
  manifest?: Record<string, unknown>;
  disableSiblingRepoLookup?: boolean;
  injectL2FailureForTest?: boolean;
  appCapabilities?: IfayReadyCapabilities;
  generatedAt?: string;
  hooks?: {
    onL2Start?: () => void;
    onL3Start?: () => void;
  };
}): IfactsReport;
