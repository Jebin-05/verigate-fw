import { api } from '../api/client';
import { Bp, ErrorLine, Hex, Panel, StatusChip, Table } from '../components/ui';
import { usePoll } from '../components/usePoll';

export function Publishers() {
  const { data, error } = usePoll(api.publishers, 5000);
  return (
    <Panel title="Publishers (PublisherRegistry)">
      <ErrorLine error={error} />
      <Table
        headers={['DID', 'status', 'reputation', 'owner', 'key', 'key v', 'registered', 'revoked']}
      >
        {(data ?? []).map((p) => (
          <tr key={p.publisherId}>
            <td>{p.did}</td>
            <td>
              <StatusChip status={p.status} />
            </td>
            <td>
              <Bp value={p.reputation} />
            </td>
            <td>
              <Hex value={p.owner} chars={6} />
            </td>
            <td>
              <Hex value={p.publicKey} chars={12} />
            </td>
            <td>{p.keyVersion}</td>
            <td>{p.registeredAt}</td>
            <td>{p.revokedAt || '—'}</td>
          </tr>
        ))}
      </Table>
    </Panel>
  );
}
