/** Response payloads of the gateway API (shapes mirror gateway/service.py and api/main.py). */
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
  rationaleCid: string | null;
  stage2?: Stage2Block | null;
}

/** The quantised feature vectors the Stage-2 models scored (what `featureHash` seals). */
export interface Stage2Block {
  sbom?: Record<string, unknown> & { top3?: [string, number][] };
  img?: Record<string, unknown> & { top3?: [string, number][]; previous?: boolean };
}

export interface RationaleStatus {
  status: 'off' | 'none' | 'writing' | 'ready' | 'failed';
  cid?: string;
  model?: string;
  rationale?: Omit<Rationale, 'cid'>;
}

export interface ModelCard {
  name: string;
  file: string;
  modelHash: string;
  metrics: Record<string, unknown> | null;
  card: string | null;
}

export interface DeviceRound {
  polls: number;
  installs: number;
  receipts: number;
  rejected: number;
  errors: number;
  lastVerdicts?: Record<string, string>;
}

export interface Rationale {
  cid: string;
  summary: string;
  top_risks: string[];
  recommended_action: 'install' | 'review' | 'block';
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

export interface RevocationReport {
  modelHash: string;
  successor: string;
  swapped: boolean;
  staleBatches: number[];
  pairs: { releaseId: string; deviceId: string; before: Verdict; after: Verdict }[];
  changed: number;
  startedAt: number;
  finishedAt: number;
  error: string | null;
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
  expected: string;
  observed: string | null;
  check: string | null;
  reason: string | null;
  release_id: string | null;
  device_id: string | null;
  details: Record<string, unknown>;
  passed: boolean;
}

/** The publisher the portal acts for (`PUBLISHER_DID` in the gateway's environment). */
export interface PublisherMe {
  did: string;
  publisherId: string;
  registered: boolean;
  status: number;
  reputation: number | null;
  publicKey: string | null;
  keyVersion: number;
}

/** `verigate-publish release` result as relayed by `POST /publisher/releases`. */
export interface PublishResult {
  releaseId: string;
  version: string;
  deviceModel: string;
  expiry: string;
  status?: string;
  txHash?: string | null;
  cids: Record<string, string>;
  fixture?: string;
}
