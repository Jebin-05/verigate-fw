/** Runnable scenarios: the walkthrough steps and their outcomes, shared by the Scenarios page. */
import { api } from '../api/client';
import type { AttackReport, Release, Verdict } from '../api/types';
import { checkText, failureWords, VERDICT_WORD } from './words';

export interface Outcome {
  headline: string;
  verdict: Verdict | null;
  label?: string; // for flow drills: Blocked / Re-checked
  detail?: string;
  releaseId?: string | null;
}

export interface Scenario {
  id: string;
  title: string;
  proves: string;
  expected: string;
  run: () => Promise<Outcome>;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitForVerdict(releaseId: string, timeoutMs = 45000): Promise<Release | null> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const r = (await api.releases()).find((x) => x.releaseId === releaseId);
    if (r?.lastVerdict) return r;
    await sleep(1500);
  }
  return null;
}

export function fromAttack(report: AttackReport): Outcome {
  const verdict =
    (['APPROVE', 'DEFER', 'REJECT'] as const).find((v) => v === report.observed) ?? null;
  const detail = report.check
    ? `Caught by “${checkText(report.check)}”. ${failureWords(report.check, report.reason)}`
    : (report.reason ?? undefined);
  return {
    headline: verdict ? VERDICT_WORD[verdict] : (report.observed ?? 'no result'),
    verdict,
    label: verdict ? undefined : (report.observed ?? undefined),
    detail,
    releaseId: report.release_id,
  };
}

export const WALKTHROUGH: Scenario[] = [
  {
    id: 'genuine',
    title: 'Genuine release',
    proves: 'A signed, registered release passes all nine checks and the risk scoring.',
    expected: 'Approved',
    run: async () => {
      const r = await api.storyPublish('v2.0.0');
      const rel = await waitForVerdict(r.releaseId);
      return {
        headline: rel?.lastVerdict ? VERDICT_WORD[rel.lastVerdict] : 'Pending',
        verdict: rel?.lastVerdict ?? null,
        detail: `Published ${r.version} (real OpenWrt 24.10 build).`,
        releaseId: r.releaseId,
      };
    },
  },
  {
    id: 'tamper',
    title: 'Tampered file',
    proves: 'Swapped bytes are rejected by cryptography before the AI is consulted.',
    expected: 'Rejected',
    run: async () => fromAttack(await api.runAttack('tamper')),
  },
  {
    id: 'vulnerable',
    title: 'Honest but outdated build',
    proves: 'Nothing forged; the AI holds a vulnerable ingredient list for review.',
    expected: 'Needs review',
    run: async () => fromAttack(await api.runAttack('vulnerable-genuine')),
  },
  {
    id: 'payload',
    title: 'Hidden payload',
    proves: 'The binary model detects 200 KB appended after the declared end.',
    expected: 'Needs review',
    run: async () => fromAttack(await api.runAttack('hidden-payload')),
  },
  {
    id: 'insider',
    title: 'Insider patch',
    proves:
      'The last good build with 256 bytes changed, signed with the real key, is held for review.',
    expected: 'Needs review',
    run: async () => fromAttack(await api.runAttack('insider-patch')),
  },
  {
    id: 'rogue',
    title: 'Compromised gateway',
    proves: 'The device reads the blockchain itself and refuses what a rogue gateway pushes.',
    expected: 'Refused',
    run: async () => {
      const report = await api.runAttack('rogue-gateway');
      const pushes =
        (report.details as { pushes?: Record<string, { installed: boolean }> }).pushes ?? {};
      const attacks = Object.entries(pushes).filter(([k]) => k !== 'control-genuine');
      const refused = attacks.filter(([, p]) => !p.installed).length;
      return {
        headline: report.passed ? 'Refused' : 'Installed',
        verdict: null,
        label: report.passed ? 'Refused' : 'Installed',
        detail: `${refused} of ${attacks.length} rogue updates refused; the genuine release still installed.`,
      };
    },
  },
  {
    id: 'rules',
    title: 'Rules tampering',
    proves: 'A non-administrator cannot change the on-chain thresholds.',
    expected: 'Blocked',
    run: async () => fromAttack(await api.runAttack('policy-tamper')),
  },
  {
    id: 'model',
    title: 'Model revocation',
    proves: 'A revoked model’s verdicts are replayed with its successor.',
    expected: 'Re-checked',
    run: async () => {
      const report = await api.runAttack('poisoned-model');
      const d = report.details as Record<string, unknown>;
      return {
        headline: report.passed ? 'Re-checked' : 'Not re-checked',
        verdict: null,
        label: report.observed ?? undefined,
        detail: `${String(d.pairsReplayed ?? 0)} verdicts replayed${d.mode === 'swap-to-successor' ? ' with the successor' : ' — no successor left, gate fails closed'}; ${String(d.changed ?? 0)} changed.`,
        releaseId: report.release_id,
      };
    },
  },
  {
    id: 'device',
    title: 'Device install cycle',
    proves: 'A device polls, verifies the file itself, installs and signs a receipt.',
    expected: 'Installed',
    run: async () => {
      const s = await api.simulateDevice();
      const verdicts = Object.values(s.lastVerdicts ?? {});
      return {
        headline:
          s.installs > 0
            ? 'Installed'
            : verdicts[0]
              ? VERDICT_WORD[verdicts[0] as Verdict]
              : 'No update',
        verdict: s.installs > 0 ? 'APPROVE' : ((verdicts[0] as Verdict) ?? null),
        label: s.installs > 0 ? 'Installed' : undefined,
        detail: `${s.polls} poll · ${s.installs} install · ${s.receipts} receipt${s.rejected ? ` · ${s.rejected} refused` : ''}`,
      };
    },
  },
];

export const DRILL_TITLES: Record<string, string> = {
  tamper: 'Tampered image',
  forge: 'Forged release',
  'stolen-key': 'Stolen key',
  rollback: 'Rollback',
  freeze: 'Freeze (expired release)',
  'sbom-swap': 'Swapped ingredient list',
  'vulnerable-genuine': 'Vulnerable but genuine',
  'hidden-payload': 'Hidden payload',
  'insider-patch': 'Insider patch',
  'rogue-gateway': 'Compromised gateway',
  'bad-history': 'Publisher with a bad history',
  'poisoned-model': 'Faulty inspection model',
  'policy-tamper': 'Rules tampering',
};

export const OUTCOME_WORD: Record<string, string> = {
  APPROVE: 'Approved',
  DEFER: 'Needs review',
  REJECT: 'Rejected',
  REPLAYED: 'Re-checked',
  BLOCKED: 'Blocked',
  REFUSED: 'Refused',
};
