/** Response payloads of the gateway API (shapes mirror gateway/service.py). */
export type Verdict = 'APPROVE' | 'REJECT' | 'DEFER';

export interface Health {
  status: string;
  chain: boolean;
  block: number | null;
  chainId: number;
  ipfsBackend: string;
  listenerLastBlock: number;
  knownReleases: number;
  devices: number;
  uptimeS: number;
  gateway: string | null;
  pendingVerdicts: number | null;
  batches: number | null;
  contracts: Record<string, string>;
}

export interface Release {
  releaseId: string;
  publisherId: string;
  deviceModel: string;
  version: string;
  manifestCid: string;
  firmwareCid: string;
  sbomCid: string;
  expiry: number;
  registeredAt: number;
  revoked: boolean;
  lastVerdict: Verdict | null;
  lastVerdictAt: string | null;
}

export interface CheckResult {
  name: string;
  ok: boolean;
  reason: string | null;
}

export interface Stage1 {
  ok: boolean;
  failed: string | null;
  reason: string | null;
  outcome: Verdict | null;
  checks: CheckResult[];
}

export interface VerificationResult {
  releaseId: string;
  deviceId: string;
  verdict: Verdict;
  reason: string | null;
  stage1: Stage1 | null;
  checkedAt: string;
  version: string | null;
  deviceModel: string | null;
  errors: string[];
  verdictId: string | null;
  R: number | null;
  policyVersion: number | null;
  rSbom: number | null;
  rImg: number | null;
  reputation: number | null;
  modelHashes: string[];
}

export interface ReceiptEvent {
  event: 'receipt';
  deviceId: string;
  releaseId: string;
  version: string;
  installedAt: string;
}

export type VerdictLogEntry = VerificationResult | ReceiptEvent;

export interface Proof {
  verdictId: string;
  status: 'pending' | 'committed';
  batchId?: number;
  root?: string;
  txHash?: string;
  blockNumber?: number;
  index?: number;
  proof?: string[];
  record?: Record<string, unknown>;
}

export interface Batch {
  batchId: number;
  root: string;
  count: number;
  txHash: string;
  blockNumber: number;
  modelHashes: string[];
  leaves: string[];
  committedAt: number;
}

export interface Device {
  device_id: string;
  device_model: string;
  public_key: string;
  installed_version: string;
  last_nonce: number;
  last_seen: number;
  installed_release_id: string | null;
  receipts: number;
}

export interface Publisher {
  publisherId: string;
  did: string;
  owner: string;
  publicKey: string;
  status: number;
  reputation: number;
  keyVersion: number;
  registeredAt: number;
  revokedAt: number;
}

export interface Model {
  modelHash: string;
  name: string;
  status: number;
  successor: string;
  registeredAt: number;
  revokedAt: number;
}

export interface Policy {
  w_sbom: number;
  w_img: number;
  w_rep: number;
  tau_approve: number;
  tau_reject: number;
  version: number;
  changed_by: string;
  changed_at: number;
}

export interface AttackReport {
  name: string;
  expected: Verdict;
  observed: Verdict | null;
  check: string | null;
  reason: string | null;
  release_id: string | null;
  device_id: string | null;
  details: Record<string, unknown>;
  passed: boolean;
}
