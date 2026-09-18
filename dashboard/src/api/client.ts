/** Typed fetch client for the gateway. Paths are checked against the generated OpenAPI schema. */
import type { paths } from './schema';
import type {
  AttackReport,
  Batch,
  Device,
  Health,
  Model,
  Policy,
  Proof,
  Publisher,
  Rationale,
  Release,
  RevocationReport,
  VerdictLogEntry,
  VerificationResult,
} from './types';

export const GATEWAY_URL: string =
  (import.meta.env.VITE_GATEWAY_URL as string | undefined) ?? 'http://localhost:8000';

type Path = keyof paths;

async function request<T>(path: Path | string, init?: RequestInit): Promise<T> {
  const resp = await fetch(GATEWAY_URL + path, {
    ...init,
    headers: { 'content-type': 'application/json', ...(init?.headers ?? {}) },
  });
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      detail = ((await resp.json()) as { detail?: string }).detail ?? detail;
    } catch {
      /* not JSON */
    }
    throw new Error(`${resp.status}: ${detail}`);
  }
  return (await resp.json()) as T;
}

export const api = {
  health: () => request<Health>('/health'),
  releases: (refresh = false) => request<Release[]>(`/releases${refresh ? '?refresh=true' : ''}`),
  release: (id: string) => request<Release & { manifest: unknown }>(`/releases/${id}`),
  verify: (id: string, deviceId?: string) =>
    request<VerificationResult>(
      `/verify/${id}${deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : ''}`,
      { method: 'POST' },
    ),
  verdicts: (limit = 200) => request<VerdictLogEntry[]>(`/verdicts?limit=${limit}`),
  proof: (verdictId: string) => request<Proof>(`/verdicts/${verdictId}/proof`),
  rationale: (cid: string) => request<Rationale>(`/rationales/${cid}`),
  batches: () => request<Batch[]>('/batches'),
  flush: () =>
    request<{ committed: Batch | null; pending: number }>('/batches/flush', { method: 'POST' }),
  devices: () => request<Device[]>('/devices'),
  publishers: () => request<Publisher[]>('/publishers'),
  models: () => request<Model[]>('/models'),
  revocations: () => request<RevocationReport[]>('/revocations'),
  checkRevocations: () => request<RevocationReport[]>('/revocations/check', { method: 'POST' }),
  policy: () => request<{ policy: Policy | null }>('/policy'),
  attacks: () => request<Record<string, { expected: string }>>('/attacks'),
  runAttack: (name: string) => request<AttackReport>(`/attacks/${name}`, { method: 'POST' }),
};

export function wsUrl(): string {
  return GATEWAY_URL.replace(/^http/, 'ws') + '/logs';
}
