import { useState } from 'react';
import { api } from '../api/client';
import type { AttackReport } from '../api/types';
import { ErrorLine, Hex, Panel, Table, VerdictBadge } from '../components/ui';
import { usePoll } from '../components/usePoll';
import { useStore } from '../state/store';

const DESCRIPTIONS: Record<string, string> = {
  tamper: 'firmware bytes behind the CID differ from what was hashed → check #1',
  forge: "attacker's key signs a manifest claiming the publisher's DID → check #2",
  'stolen-key': 'release from a key the admin has revoked → check #3',
  rollback: 'genuine older release replayed to a newer device → check #4',
  freeze: 'manifest past its expiry → check #5 → DEFER + alert (takes ~10–40 s)',
  'sbom-swap': 'clean SBOM hashed, dirty SBOM served → check #6',
};

export function Attacks() {
  const { data, error } = usePoll(api.attacks, 30000);
  const { running, setRunning } = useStore();
  const [reports, setReports] = useState<AttackReport[]>([]);

  const run = async (name: string) => {
    setRunning(name);
    try {
      const report = await api.runAttack(name);
      setReports((r) => [report, ...r]);
    } catch (err) {
      alert(String(err));
    } finally {
      setRunning(null);
    }
  };

  return (
    <>
      <Panel title="Attack scenarios (Guide §9) — run against the local emulated fleet only">
        <ErrorLine error={error} />
        <Table headers={['scenario', 'what happens', 'expected', '']}>
          {Object.entries(data ?? {}).map(([name, spec]) => (
            <tr key={name}>
              <td>
                <b>{name}</b>
              </td>
              <td>{DESCRIPTIONS[name] ?? ''}</td>
              <td>
                <VerdictBadge verdict={spec.expected as AttackReport['expected']} />
              </td>
              <td>
                <button disabled={running !== null} onClick={() => void run(name)}>
                  {running === name ? 'running…' : 'launch'}
                </button>
              </td>
            </tr>
          ))}
        </Table>
      </Panel>
      <Panel title="Reports">
        <Table
          headers={['scenario', 'expected', 'observed', 'check', 'reason', 'release', 'passed']}
        >
          {reports.map((r, i) => (
            <tr key={`${r.name}-${i}`} className={r.passed ? '' : 'row-fail'}>
              <td>{r.name}</td>
              <td>
                <VerdictBadge verdict={r.expected} />
              </td>
              <td>
                <VerdictBadge verdict={r.observed} />
              </td>
              <td>{r.check ?? '—'}</td>
              <td>{r.reason ?? '—'}</td>
              <td>
                <Hex value={r.release_id} />
              </td>
              <td>{r.passed ? '✔' : '✘'}</td>
            </tr>
          ))}
        </Table>
      </Panel>
    </>
  );
}
