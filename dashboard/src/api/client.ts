/** Typed fetch client for the gateway. Paths are checked against the generated OpenAPI schema. */
import type { paths } from './schema';
import type {
  AiAnalysis,
  AttackReport,
  Device,
  DeviceRound,
  Health,
  Model,
  ModelCard,
  Policy,
  Proof,
  Publisher,
  PublisherMe,
  PublishResult,
  Rationale,
  RationaleStatus,
  Release,
  Review,
  RevocationReport,
  VerdictLogEntry,
  VerificationResult,
} from './types';

export const GATEWAY_URL: string =
  (import.meta.env.VITE_GATEWAY_URL as string | undefined) ?? 'http://localhost:8000';

type Path = keyof paths;

async function request<T>(path: Path | string, init?: RequestInit): Promise<T> {
  const isForm = init?.body instanceof FormData;
  const resp = await fetch(GATEWAY_URL + path, {
    ...init,
    headers: {
      ...(isForm ? {} : { 'content-type': 'application/json' }),
      ...(init?.headers ?? {}),
    },
  });
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      const body = (await resp.json()) as { detail?: unknown };
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* not JSON */
    }
    throw new Error(detail || `HTTP ${resp.status}`);
  }
  return (await resp.json()) as T;
}

export const api = {
  health: () => request<Health>('/health'),
  releases: () => request<Release[]>('/releases'),
  verdicts: (limit = 500) => request<VerdictLogEntry[]>(`/verdicts?limit=${limit}`),
  proof: (verdictId: string) => request<Proof>(`/verdicts/${verdictId}/proof`),
  rationale: (cid: string) => request<Rationale>(`/rationales/${cid}`),
  rationaleStatus: (releaseId: string) =>
    request<RationaleStatus>(`/releases/${releaseId}/rationale`),
  explain: (releaseId: string, again = false) =>
    request<RationaleStatus>(`/releases/${releaseId}/explain${again ? '?again=true' : ''}`, {
      method: 'POST',
    }),
  analysis: (releaseId: string) => request<AiAnalysis>(`/releases/${releaseId}/analysis`),
  analyse: (releaseId: string) =>
    request<AiAnalysis>(`/releases/${releaseId}/analyse`, { method: 'POST' }),
  modelCards: () => request<ModelCard[]>('/models/cards'),
  devices: () => request<Device[]>('/devices'),
  publishers: () => request<Publisher[]>('/publishers'),
  models: () => request<Model[]>('/models'),
  revocations: () => request<RevocationReport[]>('/revocations'),
  policy: () => request<{ policy: Policy | null }>('/policy'),
  verify: (id: string) => request<VerificationResult>(`/verify/${id}`, { method: 'POST' }),
  review: (id: string, decision: 'APPROVE' | 'REJECT', reviewer: string, note: string) =>
    request<{ review: Review; verdict: VerificationResult }>(`/releases/${id}/review`, {
      method: 'POST',
      body: JSON.stringify({ decision, reviewer, note }),
    }),
  // publisher portal
  me: () => request<PublisherMe>('/publisher/me'),
  publish: (form: FormData) =>
    request<PublishResult>('/publisher/releases', { method: 'POST', body: form }),
  withdraw: (id: string) =>
    request<{ status: string }>(`/publisher/releases/${id}/withdraw`, { method: 'POST' }),
  // demonstrations
  storyPublish: (fixture: string) =>
    request<PublishResult>(`/story/publish?fixture=${encodeURIComponent(fixture)}`, {
      method: 'POST',
    }),
  simulateDevice: () => request<DeviceRound>('/simulate/device', { method: 'POST' }),
  attacks: () => request<Record<string, { expected: string }>>('/attacks'),
  runAttack: (name: string) => request<AttackReport>(`/attacks/${name}`, { method: 'POST' }),
};

export function wsUrl(): string {
  return GATEWAY_URL.replace(/^http/, 'ws') + '/logs';
}
