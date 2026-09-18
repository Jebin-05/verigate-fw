import { api } from '../api/client';
import { ErrorLine, Hex, Panel, Table } from '../components/ui';
import { usePoll } from '../components/usePoll';

export function Fleet() {
  const { data, error } = usePoll(api.devices, 3000);
  return (
    <Panel title="Fleet (devices that said hello)">
      <ErrorLine error={error} />
      <Table
        headers={[
          'device',
          'model',
          'installed',
          'release',
          'receipts',
          'nonce',
          'last seen',
          'key',
        ]}
      >
        {(data ?? []).map((d) => (
          <tr key={d.device_id}>
            <td>{d.device_id}</td>
            <td>{d.device_model}</td>
            <td>{d.installed_version}</td>
            <td>
              <Hex value={d.installed_release_id} />
            </td>
            <td>{d.receipts}</td>
            <td>{d.last_nonce}</td>
            <td>{new Date(d.last_seen * 1000).toLocaleTimeString()}</td>
            <td>
              <Hex value={d.public_key} chars={12} />
            </td>
          </tr>
        ))}
      </Table>
    </Panel>
  );
}
