export type CheckSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type CheckStatus = 'PASS' | 'FAIL' | 'WARN' | 'SKIPPED';

export type EvidenceQuality = 'VERIFIED' | 'PARTIAL' | 'STATIC-ONLY';

export type Dimension = 'D1' | 'D2' | 'D3' | 'D4' | 'D5';

export type VetoClass = 'VETO_NONE' | 'VETO_PANIC' | 'VETO_INJECT' | 'VETO_DATALOSS';

export type CertificationTier = 'Platinum' | 'Gold' | 'Silver' | 'Bronze' | 'Failed';

export interface CodeDiff {
  language: 'typescript-zod' | 'python-fastmcp' | 'go' | 'json-schema';
  code: string;
}

export interface CheckEvidence {
  requestsSent?: number;
  mutationsCreated?: number;
  expectedMutations?: number;
  evidenceQuality: EvidenceQuality;
  details?: Record<string, unknown>;
}

export interface CheckFix {
  summary: string;
  applyCommand?: string;
  diffs: CodeDiff[];
}

export interface CheckResult {
  checkId: string;
  dimension: Dimension;
  tool: string;
  status: CheckStatus;
  severity: CheckSeverity;
  description: string;
  evidence: CheckEvidence;
  fix?: CheckFix;
  durationMs: number;
  llmTokensUsed?: number;
}

export interface ToolParameterSchema {
  type: string;
  description?: string;
  properties?: Record<string, any>;
  required?: string[];
  additionalProperties?: boolean;
}

export interface McpToolDefinition {
  name: string;
  description?: string;
  inputSchema: ToolParameterSchema;
  isMutation?: boolean;
  idempotentHint?: boolean;
}

export interface McpCallRequest {
  method: string;
  params: {
    name: string;
    arguments?: Record<string, any>;
  };
}

export interface McpCallResponse {
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}

export interface DimensionalScore {
  score: number;
  weight: number;
  metrics: Record<string, number>;
}

export interface SuiteSummary {
  target: string;
  totalChecks: number;
  passed: number;
  failed: number;
  warned: number;
  fatalVetoTriggered: boolean;
  fatalVetoCode: VetoClass;
  phi: number; // 0.0, 0.25, 0.5, 1.0
  score: number; // 0 - 100
  tier: CertificationTier;
  durationMs: number;
  llmTokensUsed: number;
  dimensionalScores: Record<Dimension, DimensionalScore>;
  results: CheckResult[];
}
