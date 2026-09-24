/** Devices: every device that has checked in, what it runs, and its receipts. */
import { Link } from 'react-router-dom';
import { api } from '../../api/client';
import { Empty, Id, Kpi, Panel } from '../../components/Bits';
import { usePoll } from '../../components/usePoll';

function since(epoch: number): string {
  if (!epoch) return '—';
  const s = Math.max(0, Math.floor(Date.now() / 1000 - epoch));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function Devices() {
  const devices = usePoll(api.devices, 4000);
  const releases = usePoll(api.releases, 5000);
  const list = (devices.data ?? []).slice().sort((a, b) => b.last_seen - a.last_seen);
  const byVersion = new Map<string, number>();
  for (const d of list)
    byVersion.set(d.installed_version, (byVersion.get(d.installed_version) ?? 0) + 1);
  const latest = (releases.data ?? [])
    .filter((r) => r.lastVerdict === 'APPROVE' && !r.revoked)
    .at(-1);
  const onLatest = latest
    ? list.filter((d) => d.installed_release_id === latest.releaseId).length
    : 0;
  const versionOf = (id: string | null) =>
    (releases.data ?? []).find((r) => r.releaseId === id)?.version ?? null;
  return (
    <>
      <div className="kpis">
        <Kpi label="Devices checked in" value={list.length} />
        <Kpi
          label="On the latest approved release"
          value={onLatest}
          sub={latest ? latest.version : 'no approved release'}
        />
        <Kpi
          label="Versions in the field"
          value={byVersion.size}
          sub={[...byVersion.entries()].map(([v, n]) => `${v} ×${n}`).join(' · ')}
        />
        <Kpi label="Receipts received" value={list.reduce((a, d) => a + d.receipts, 0)} />
      </div>
      <Panel title="Devices" flush>
        {list.length === 0 ? (
          <Empty>No device has checked in yet.</Empty>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Device</th>
                <th>Model</th>
                <th>Installed version</th>
                <th>Installed release</th>
                <th className="num">Receipts</th>
                <th>Last seen</th>
                <th>Key</th>
              </tr>
            </thead>
            <tbody>
              {list.map((d) => (
                <tr key={d.device_id}>
                  <td>
                    <b>{d.device_id}</b>
                  </td>
                  <td>{d.device_model}</td>
                  <td>{d.installed_version}</td>
                  <td>
                    {d.installed_release_id ? (
                      <Link to={`/app/releases?r=${d.installed_release_id}`}>
                        {versionOf(d.installed_release_id) ?? <Id value={d.installed_release_id} />}
                      </Link>
                    ) : (
                      <span className="faint">—</span>
                    )}
                  </td>
                  <td className="num">{d.receipts}</td>
                  <td className="muted">{since(d.last_seen)}</td>
                  <td>
                    <Id value={d.public_key} chars={10} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </>
  );
}
