import { api } from '../api/client';
import { Bp, ErrorLine, Hex, Panel, Table } from '../components/ui';
import { usePoll } from '../components/usePoll';

export function Policy() {
  const { data, error } = usePoll(api.policy, 5000);
  const p = data?.policy ?? null;
  return (
    <Panel title="Policy (PolicyContract) — changing it is an on-chain transaction">
      <ErrorLine error={error} />
      {p ? (
        <>
          <p className="formula">
            R = <Bp value={p.w_sbom} /> · r_sbom + <Bp value={p.w_img} /> · r_img +{' '}
            <Bp value={p.w_rep} /> · (1 − reputation)
          </p>
          <Table headers={['parameter', 'basis points', 'value']}>
            {(
              [
                ['w_sbom', p.w_sbom],
                ['w_img', p.w_img],
                ['w_rep', p.w_rep],
                ['tau_approve (R below → APPROVE)', p.tau_approve],
                ['tau_reject (R at/above → REJECT)', p.tau_reject],
              ] as const
            ).map(([name, value]) => (
              <tr key={name}>
                <td>{name}</td>
                <td>{value}</td>
                <td>
                  <Bp value={value} />
                </td>
              </tr>
            ))}
          </Table>
          <p className="muted">
            version {p.version} · changed by <Hex value={p.changed_by} chars={6} /> at block{' '}
            {p.changed_at}
          </p>
        </>
      ) : (
        <p className="error">
          policy unavailable (chain unreachable) — the gateway defers in this state
        </p>
      )}
    </Panel>
  );
}
