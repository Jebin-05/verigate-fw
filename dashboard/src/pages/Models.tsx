import { api } from '../api/client';
import { ErrorLine, Hex, Panel, StatusChip, Table } from '../components/ui';
import { usePoll } from '../components/usePoll';

export function Models() {
  const { data, error } = usePoll(api.models, 5000);
  return (
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
              <Hex value={m.successor === '0x' + '0'.repeat(64) ? null : m.successor} />
            </td>
            <td>{m.registeredAt}</td>
            <td>{m.revokedAt || '—'}</td>
          </tr>
        ))}
      </Table>
    </Panel>
  );
}
