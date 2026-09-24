/** Security drills for demonstrations: run a scripted attack, then watch the gate catch it. */
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { AttackReport } from '../api/types';
import { usePoll } from '../components/usePoll';
import { useStore } from '../state/store';

const DRILLS: Record<string, { title: string; story: string; caught: string }> = {
  tamper: {
    title: 'Tampered image',
    story: 'The bytes behind the download link are not the bytes the publisher signed.',
    caught: 'Rejected — the firmware fingerprint does not match.',
  },
  forge: {
    title: 'Forged release',
    story: 'An attacker signs a release with their own key and claims to be the real publisher.',
    caught: 'Rejected — the signature is not from the publisher’s registered key.',
  },
  'stolen-key': {
    title: 'Stolen key',
    story: 'A release signed with a key the publisher has already revoked.',
    caught: 'Rejected — the publisher’s key is no longer in good standing.',
  },
  rollback: {
    title: 'Rollback',
    story: 'A genuine but older release is replayed to a device that already runs a newer one.',
    caught: 'Rejected — older than what the device has.',
  },
  freeze: {
    title: 'Freeze',
    story: 'Devices are prevented from seeing anything newer than an expired release.',
    caught: 'Held for review — the release has expired, and an alert is raised.',
  },
  'sbom-swap': {
    title: 'Swapped ingredient list',
    story: 'A clean ingredient list is signed, but a different one is served with the firmware.',
    caught: 'Rejected — the ingredient list does not match its fingerprint.',
  },
  'vulnerable-genuine': {
    title: 'Vulnerable but genuine',
    story:
      'An honest publisher ships a build on an end-of-life base with many known vulnerabilities.',
    caught: 'Held for review — every check passes, but the risk score is too high to approve.',
  },
  'hidden-payload': {
    title: 'Hidden payload',
    story: 'A genuine-looking build with 200 KB of packed code appended to it.',
    caught: 'Held for review — the binary looks structurally unusual.',
  },
  'bad-history': {
    title: 'Publisher with a bad history',
    story: 'A publisher with several recent rejections ships a borderline release.',
    caught: 'Held for review — the same release from a publisher in good standing is approved.',
  },
  'poisoned-model': {
    title: 'Faulty inspection model',
    story: 'An inspection model is found to have a blind spot and is revoked by the administrator.',
    caught: 'Every verdict it produced is re-checked with its successor.',
  },
  'policy-tamper': {
    title: 'Rules tampering',
    story: 'Someone without administrator rights tries to lower the approval line.',
    caught: 'Blocked — the blockchain refuses the change; the rules are unchanged.',
  },
};

const OUTCOME: Record<string, string> = {
  APPROVE: 'Approved',
  DEFER: 'Held for review',
  REJECT: 'Rejected',
  REPLAYED: 'Re-checked',
  BLOCKED: 'Blocked',
};

export function Drills() {
  const { data, error } = usePoll(api.attacks, 30000);
  const { running, setRunning } = useStore();
  const [reports, setReports] = useState<AttackReport[]>([]);

  const run = async (name: string) => {
    setRunning(name);
    try {
      const report = await api.runAttack(name);
      setReports((r) => [report, ...r]);
    } catch (err) {
      window.alert(`The drill could not run: ${(err as Error).message}`);
    } finally {
      setRunning(null);
    }
  };

  return (
    <main className="page narrow">
      <div className="page-head">
        <h1>Security drills</h1>
        <p>
          Each drill stages a real attack against the local test fleet and asks the gate to judge
          it. Open the <Link to="/approve">approval console</Link> beside this page to watch the
          verdict arrive.
        </p>
      </div>
      {error && <p className="notice bad">Could not reach the gateway: {error}</p>}
      <section className="block">
        <table className="drills">
          <thead>
            <tr>
              <th>Drill</th>
              <th>What happens</th>
              <th>What the gate does</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {Object.keys(data ?? {}).map((name) => {
              const d = DRILLS[name] ?? { title: name, story: '', caught: '' };
              return (
                <tr key={name}>
                  <td>
                    <b>{d.title}</b>
                  </td>
                  <td>{d.story}</td>
                  <td>{d.caught}</td>
                  <td>
                    <button disabled={running !== null} onClick={() => void run(name)}>
                      {running === name ? 'Running…' : 'Run'}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
      {reports.length > 0 && (
        <section className="block">
          <h2>Results</h2>
          <ul className="rows">
            {reports.map((r, i) => (
              <li key={`${r.name}-${i}`}>
                <div>
                  <div className="title">{DRILLS[r.name]?.title ?? r.name}</div>
                  <div className="sub">
                    Expected {OUTCOME[r.expected] ?? r.expected}, got{' '}
                    {r.observed ? (OUTCOME[r.observed] ?? r.observed) : 'no result'}
                    {r.check ? ` — caught by “${r.check.replace(/_/g, ' ')}”` : ''}
                  </div>
                </div>
                <span className={`stamp ${r.passed ? 'ok' : 'bad'}`}>
                  {r.passed ? 'Caught' : 'Missed'}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </main>
  );
}
