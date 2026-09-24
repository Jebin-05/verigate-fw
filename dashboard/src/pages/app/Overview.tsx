/** Overview: fleet-wide numbers, the latest releases and live activity. */
import { Link, useOutletContext } from 'react-router-dom';
import { api } from '../../api/client';
import type { Health } from '../../api/types';
import { ActivityFeed } from '../../components/Activity';
import { Empty, Kpi, Panel, Stamp } from '../../components/Bits';
import { usePoll } from '../../components/usePoll';
import { bp, fmtDate } from '../../lib/words';

export function Overview() {
  const health = useOutletContext<Health | null>();
  const releases = usePoll(api.releases, 4000);
  const devices = usePoll(api.devices, 5000);
  const policy = usePoll(api.policy, 15000);
  const list = (releases.data ?? []).slice().reverse();
  const counts = { APPROVE: 0, DEFER: 0, REJECT: 0, pending: 0 };
  for (const r of releases.data ?? []) {
    if (r.revoked) continue;
    if (r.lastVerdict) counts[r.lastVerdict] += 1;
    else counts.pending += 1;
  }
  const p = policy.data?.policy ?? null;
  return (
    <>
      <div className="kpis">
        <Kpi
          label="Releases"
          value={releases.data?.length ?? '—'}
          sub={`${counts.pending} pending inspection`}
        />
        <Kpi label="Approved" value={<span className="ok">{counts.APPROVE}</span>} />
        <Kpi label="Needs review" value={<span className="warn">{counts.DEFER}</span>} />
        <Kpi label="Rejected" value={<span className="bad">{counts.REJECT}</span>} />
        <Kpi label="Devices" value={devices.data?.length ?? '—'} sub="checked in" />
        <Kpi
          label="Anchored on-chain"
          value={health?.batches ?? '—'}
          sub={`batches · ${health?.pendingVerdicts ?? 0} verdicts pending`}
        />
      </div>
      <div className="three">
        <Panel
          title="Latest releases"
          flush
          actions={
            <Link className="btn btn-sm" to="/app/releases">
              All releases
            </Link>
          }
        >
          {list.length === 0 ? (
            <Empty>No releases registered yet.</Empty>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Version</th>
                  <th>Model</th>
                  <th>Verdict</th>
                  <th>Inspected</th>
                </tr>
              </thead>
              <tbody>
                {list.slice(0, 8).map((r) => (
                  <tr key={r.releaseId}>
                    <td>
                      <Link to={`/app/releases?r=${r.releaseId}`}>{r.version}</Link>
                    </td>
                    <td>{r.deviceModel}</td>
                    <td>
                      <Stamp verdict={r.lastVerdict} revoked={r.revoked} />
                    </td>
                    <td className="muted">{fmtDate(r.lastVerdictAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
        <div style={{ display: 'grid', gap: 16 }}>
          <Panel title="Rules in force">
            {p ? (
              <dl className="kv">
                <dt>Approve below</dt>
                <dd>{bp(p.tau_approve)}</dd>
                <dt>Reject from</dt>
                <dd>{bp(p.tau_reject)}</dd>
                <dt>Weights</dt>
                <dd>
                  ingredients {bp(p.w_sbom)} · binary {bp(p.w_img)} · publisher {bp(p.w_rep)}
                </dd>
                <dt>Version</dt>
                <dd>{p.version}</dd>
              </dl>
            ) : (
              <span className="muted">Unavailable</span>
            )}
          </Panel>
          <Panel
            title="Live activity"
            flush
            actions={
              <Link className="btn btn-sm" to="/app/activity">
                Full log
              </Link>
            }
          >
            <ActivityFeed limit={12} />
          </Panel>
        </div>
      </div>
    </>
  );
}
