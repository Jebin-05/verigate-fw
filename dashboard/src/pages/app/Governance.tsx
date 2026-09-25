/** Governance: rules in force + simulator, inspection models + cards, revocation replays. */
import { useMemo } from 'react';
import { api } from '../../api/client';
import type { VerificationResult } from '../../api/types';
import { Empty, Id, Panel } from '../../components/Bits';
import { ModelCards, RulesSimulator } from '../../components/Insight';
import { usePoll } from '../../components/usePoll';
import { bp, fmtDate, isVerdict, simulate } from '../../lib/words';
import { useSim } from '../../state/store';

const STATUS: Record<number, { label: string; tone: string }> = {
  0: { label: 'Not registered', tone: 'none' },
  1: { label: 'Active', tone: 'ok' },
  2: { label: 'Revoked', tone: 'bad' },
};

export function Governance() {
  const policy = usePoll(api.policy, 15000);
  const models = usePoll(api.models, 15000);
  const revocations = usePoll(api.revocations, 15000);
  const releases = usePoll(api.releases, 5000);
  const verdicts = usePoll(api.verdicts, 5000);
  const { sim, setSim } = useSim();
  const p = policy.data?.policy ?? null;

  const changed = useMemo(() => {
    if (!sim) return 0;
    const fleet = new Map<string, VerificationResult>();
    for (const e of (verdicts.data ?? []).filter(isVerdict))
      if (e.deviceId === 'release-level') fleet.set(e.releaseId, e);
    return (releases.data ?? []).filter((r) => {
      const f = fleet.get(r.releaseId);
      return f && simulate(f.verdict, f.stage1?.ok ?? null, f.R, sim) !== f.verdict;
    }).length;
  }, [sim, verdicts.data, releases.data]);

  return (
    <div className="two">
      <div style={{ display: 'grid', gap: 16 }}>
        <Panel title="Rules in force">
          {p ? (
            <dl className="kv">
              <dt>Approve below</dt>
              <dd>{bp(p.tau_approve)} overall risk</dd>
              <dt>Review between</dt>
              <dd>
                {bp(p.tau_approve)} and {bp(p.tau_reject)}
              </dd>
              <dt>Reject from</dt>
              <dd>{bp(p.tau_reject)}</dd>
              <dt>Weights</dt>
              <dd>
                ingredients {bp(p.w_sbom)} · binary {bp(p.w_img)} · publisher standing {bp(p.w_rep)}
              </dd>
              <dt>Policy version</dt>
              <dd>{p.version}</dd>
              <dt>Set by</dt>
              <dd>
                <Id value={p.changed_by} chars={10} />
              </dd>
            </dl>
          ) : (
            <Empty>Rules unavailable.</Empty>
          )}
        </Panel>
        <Panel>
          <RulesSimulator policy={p} sim={sim} setSim={setSim} changed={changed} />
        </Panel>
      </div>
      <div style={{ display: 'grid', gap: 16 }}>
        <Panel title="Inspection models" flush>
          {(models.data ?? []).length === 0 ? (
            <Empty>No models registered.</Empty>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Status</th>
                  <th>Hash</th>
                  <th>Successor</th>
                </tr>
              </thead>
              <tbody>
                {(models.data ?? []).map((m) => (
                  <tr key={m.modelHash}>
                    <td>{m.name || '—'}</td>
                    <td>
                      <span className={`stamp ${STATUS[m.status]?.tone ?? 'none'}`}>
                        {STATUS[m.status]?.label ?? m.status}
                      </span>
                    </td>
                    <td>
                      <Id value={m.modelHash} />
                    </td>
                    <td>
                      <Id value={m.successor === '0x' + '0'.repeat(64) ? null : m.successor} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
        <Panel>
          <ModelCards />
        </Panel>
        <Panel title="Revocation replays" flush>
          {(revocations.data ?? []).length === 0 ? (
            <Empty>No model has been revoked on this gateway.</Empty>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>When</th>
                  <th>Revoked</th>
                  <th>Successor</th>
                  <th className="num">Replayed</th>
                  <th className="num">Changed</th>
                </tr>
              </thead>
              <tbody>
                {(revocations.data ?? []).map((r) => (
                  <tr key={r.modelHash}>
                    <td className="muted">{fmtDate(new Date(r.startedAt * 1000).toISOString())}</td>
                    <td>
                      <Id value={r.modelHash} />
                    </td>
                    <td>
                      {r.swapped ? (
                        <Id value={r.successor} />
                      ) : (
                        <span className="bad">none — fail closed</span>
                      )}
                    </td>
                    <td className="num">{r.pairs.length}</td>
                    <td className="num">{r.changed}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>
    </div>
  );
}
