/** Everything the interface says in plain words lives here, so both portals speak the same way. */
import type { LogEvent } from '../state/store';
import type { Verdict, VerificationResult } from '../api/types';

export type Tone = 'ok' | 'warn' | 'bad' | 'none';

export const VERDICT_WORD: Record<Verdict, string> = {
  APPROVE: 'Approved',
  DEFER: 'Needs review',
  REJECT: 'Rejected',
};

export const VERDICT_TONE: Record<Verdict, Tone> = {
  APPROVE: 'ok',
  DEFER: 'warn',
  REJECT: 'bad',
};

/** The eight Stage-1 checks, as a person would say them. Order = the order the gateway runs. */
export const CHECKS: { name: string; text: string }[] = [
  { name: 'firmware_hash', text: 'Firmware file matches its fingerprint' },
  { name: 'signature', text: 'Signed by the publisher’s registered key' },
  { name: 'publisher_active', text: 'Publisher is in good standing' },
  { name: 'version_monotonic', text: 'Newer than the version already on the device' },
  { name: 'expiry', text: 'Not expired' },
  { name: 'sbom_hash', text: 'Ingredient list (SBOM) matches its fingerprint' },
  { name: 'registry_record', text: 'Still listed by the publisher, not withdrawn' },
  { name: 'model_active', text: 'Inspection models are current' },
];

export function checkText(name: string | null | undefined): string {
  return CHECKS.find((c) => c.name === name)?.text ?? name ?? 'a check';
}

/** Why a check failed, in words a reviewer can act on. The raw reason stays available elsewhere. */
export function failureWords(
  name: string | null | undefined,
  reason: string | null | undefined,
): string {
  const r = reason ?? '';
  switch (name) {
    case 'firmware_hash':
      return 'The firmware file that was served is not the file the publisher signed.';
    case 'sbom_hash':
      return 'The ingredient list that was served is not the one the publisher signed.';
    case 'signature':
      return 'The signature does not verify under the key registered for this publisher.';
    case 'publisher_active':
      return r.includes('revoked')
        ? 'The publisher’s key has been revoked.'
        : 'The publisher is not registered or not in good standing.';
    case 'version_monotonic': {
      const m = /^([\d.]+) <= installed ([\d.]+)$/.exec(r);
      if (m)
        return `Version ${m[1]} is not newer than the ${m[2]} already installed on the device.`;
      return r.startsWith('release is for')
        ? `This release is for a different device model (${r}).`
        : 'The version is not newer than what the device runs.';
    }
    case 'expiry':
      return 'The release has passed its expiry date.';
    case 'registry_record':
      return r.includes('revoked')
        ? 'The publisher has withdrawn this release.'
        : 'The release is not listed on the blockchain.';
    case 'model_active':
      return 'One of the inspection models has been revoked or is not registered, so the gate cannot vouch for the result.';
    default:
      return r || 'The check failed.';
  }
}

export function shortId(hex: string | null | undefined, chars = 8): string {
  if (!hex) return '—';
  return hex.length > chars + 4 ? `${hex.slice(0, chars + 2)}…${hex.slice(-3)}` : hex;
}

export function bp(value: number | null | undefined): string {
  return value === null || value === undefined ? '—' : (value / 10000).toFixed(2);
}

export function standing(bp: number | null | undefined): { label: string; tone: Tone } {
  if (bp === null || bp === undefined) return { label: 'unknown', tone: 'none' };
  if (bp >= 7000) return { label: 'excellent', tone: 'ok' };
  if (bp >= 4500) return { label: 'good', tone: 'ok' };
  if (bp >= 2500) return { label: 'shaky', tone: 'warn' };
  return { label: 'poor', tone: 'bad' };
}

/** One sentence that explains a verdict without any of the gateway's vocabulary. */
export function reasonWords(v: VerificationResult): string {
  const reason = v.reason ?? '';
  if (reason.startsWith('dependency unavailable')) {
    return 'The blockchain or the file store could not be reached, so the decision is on hold. It will be retried.';
  }
  if (v.stage1 && !v.stage1.ok && v.stage1.failed) {
    const check = checkText(v.stage1.failed);
    if (v.stage1.failed === 'expiry') {
      return `Held for review: the release has expired (${check.toLowerCase()} failed). Someone may be blocking newer releases from reaching devices.`;
    }
    return `Rejected before any risk scoring — “${check}” failed. ${failureWords(v.stage1.failed, v.stage1.reason)}`;
  }
  const m = /R=([\d.]+) vs tau_approve=([\d.]+), tau_reject=([\d.]+)/.exec(reason);
  if (m) {
    const [r, a, rj] = [m[1], m[2], m[3]].map((x) => Number(x).toFixed(2));
    if (v.verdict === 'APPROVE')
      return `All eight checks passed and the overall risk ${r} is below the approval line ${a}.`;
    if (v.verdict === 'DEFER')
      return `All eight checks passed, but the overall risk ${r} sits between ${a} and ${rj}, so a person has to decide.`;
    return `All eight checks passed, yet the overall risk ${r} is at or above the rejection line ${rj}.`;
  }
  return reason || VERDICT_WORD[v.verdict];
}

export function fmtTime(iso: string | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleTimeString([], { hour12: false });
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  return d.toLocaleString([], {
    day: 'numeric',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

export interface Line {
  text: string;
  tone: Tone;
}

/** Turn a structured gateway event into one sentence, or `null` to leave it out of the feed. */
export function describeEvent(e: LogEvent): Line | null {
  const s = (k: string) => (typeof e[k] === 'string' ? (e[k] as string) : undefined);
  const device = s('device_id');
  const where = !device || device === 'release-level' ? 'for the fleet' : `for device ${device}`;
  const release = `release ${shortId(s('release_id'), 6)}`;
  switch (e.event) {
    case 'verify.verdict': {
      const verdict = s('verdict') as Verdict | undefined;
      const failed = s('failed');
      if (!verdict) return null;
      const why = failed ? ` — ${checkText(failed).toLowerCase()} failed` : '';
      return {
        text: `${VERDICT_WORD[verdict]}: ${release} ${where}${why}`,
        tone: VERDICT_TONE[verdict],
      };
    }
    case 'verify.deferred':
      return { text: `On hold: ${release} ${where} — a dependency was unreachable`, tone: 'warn' };
    case 'listener.new_release':
      return { text: `New release registered on the blockchain (${release})`, tone: 'none' };
    case 'batch.committed':
      return {
        text: `${String(e.count ?? '')} verdicts anchored on the blockchain (batch ${String(e.batch_id ?? '')}, block ${String(e.block ?? '')})`,
        tone: 'ok',
      };
    case 'device.hello':
      return {
        text: `Device ${device ?? ''} checked in, running ${s('version') ?? '?'}`,
        tone: 'none',
      };
    case 'device.receipt':
      return {
        text: `Device ${device ?? ''} installed ${s('version') ?? ''} and sent a signed receipt`,
        tone: 'ok',
      };
    case 'reputation.updated':
      return {
        text: `Publisher standing updated to ${bp(e.reputation_bp as number)} (${s('why') ?? ''})`,
        tone: 'none',
      };
    case 'revocation.detected':
      return {
        text: `An inspection model was revoked — re-checking every verdict it produced`,
        tone: 'warn',
      };
    case 'model.swapped':
      return { text: `Successor inspection model loaded`, tone: 'ok' };
    case 'model.swap_unavailable':
      return {
        text: `No successor model available — the gate now rejects until one is registered`,
        tone: 'bad',
      };
    case 'revocation.reverified':
      return {
        text: `Re-check finished: ${String(e.pairs ?? '')} verdicts replayed, ${String(e.changed ?? 0)} changed`,
        tone: 'ok',
      };
    case 'explain.ok':
      return { text: `Written explanation attached to ${release}`, tone: 'none' };
    case 'protocol.rejected':
      return {
        text: `A device message was refused (${s('reason') ?? 'bad signature or replay'})`,
        tone: 'bad',
      };
    case 'gateway.started':
      return { text: 'Gateway started', tone: 'none' };
    case 'listener.chain_reset':
      return { text: 'The blockchain was reset — re-reading every release', tone: 'warn' };
    default:
      return null; // per-check traces, HTTP access lines and internals stay out of the feed
  }
}
