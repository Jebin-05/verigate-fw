import { api } from '../api/client';
import { ErrorLine, Hex, Panel, StatusChip, Table, VerdictBadge } from '../components/ui';
import { usePoll } from '../components/usePoll';

const ZERO = '0x' + '0'.repeat(64);

export function Models() {
  const { data, error } = usePoll(api.models, 5000);
  const revocations = usePoll(api.revocations, 5000);
  return (
    <>
      <Panel title="AI models (ModelRegistry)">
        <ErrorLine error={error} />
        {data && data.length === 0 && (
          <p className="muted">No model registered yet — Stage 2 models arrive in P5/P6.</p>
        )}
        <Table headers={['hash', 'name', 'status', 'successor', 'registered', 'revoked at']}>
          {(data ?? []).map((m) => (
            <tr key={m.modelHash}>
              <td>
                <Hex value={m.modelHash} />
              </td>
              <td>{m.name}</td>
              <td>
                <StatusChip status={m.status} />
              </td>
              <td>
                <Hex value={m.successor === ZERO ? null : m.successor} />
              </td>
              <td>{m.registeredAt}</td>
              <td>{m.revokedAt || '—'}</td>
            </tr>
          ))}
        </Table>
      </Panel>
      <Panel
        title="Model revocations replayed by this gateway (before → after)"
        actions={
          <button onClick={() => void api.checkRevocations().then(() => revocations.refresh())}>
            check now
          </button>
        }
      >
        <ErrorLine error={revocations.error} />
        {revocations.data && revocations.data.length === 0 && (
          <p className="muted">
            None yet. <code>verigate-admin revoke-model &lt;hash&gt; --successor &lt;hash&gt;</code>{' '}
            marks every batch that used the model STALE; the gateway swaps in the successor (found
            by hash under <code>MODELS_DIR</code>) and re-verifies each affected release / device.
          </p>
        )}
        {(revocations.data ?? []).map((r) => (
          <div key={r.modelHash}>
            <p>
              revoked <Hex value={r.modelHash} /> → successor{' '}
              <Hex value={r.successor === ZERO ? null : r.successor} /> ·{' '}
              {r.swapped ? 'swapped' : 'no successor file — fail closed'} · stale batches{' '}
              {r.staleBatches.join(', ') || '—'} · {r.pairs.length} verdicts replayed,{' '}
              <b>{r.changed} changed</b>
              {r.error ? <span className="bad"> · {r.error}</span> : null}
            </p>
            <Table headers={['release', 'device', 'before', 'R', 'after', 'R', 'new verdict id']}>
              {r.pairs.map((p) => (
                <tr key={p.releaseId + p.deviceId}>
                  <td>
                    <Hex value={p.releaseId} />
                  </td>
                  <td>{p.deviceId}</td>
                  <td>
                    <VerdictBadge verdict={p.before} />
                  </td>
                  <td>{p.rBefore}</td>
                  <td>
                    <VerdictBadge verdict={p.after} />
                  </td>
                  <td>{p.rAfter ?? '—'}</td>
                  <td>
                    <Hex value={p.afterId} />
                  </td>
                </tr>
              ))}
            </Table>
          </div>
        ))}
      </Panel>
    </>
  );
}
