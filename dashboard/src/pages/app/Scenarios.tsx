/** Scenarios: the walkthrough as a runnable suite, plus every raw drill. */
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../../api/client';
import type { AttackReport } from '../../api/types';
import { Empty, Panel, Stamp } from '../../components/Bits';
import { usePoll } from '../../components/usePoll';
import { DRILL_TITLES, OUTCOME_WORD, WALKTHROUGH, type Outcome } from '../../lib/scenarios';
import { useStore } from '../../state/store';

type Run =
  | { state: 'idle' }
  | { state: 'running' }
  | { state: 'done'; outcome: Outcome }
  | { state: 'failed'; error: string };

export function Scenarios() {
  const [runs, setRuns] = useState<Record<string, Run>>({});
  const { running, setRunning } = useStore();
  const drills = usePoll(api.attacks, 30000);
  const [reports, setReports] = useState<AttackReport[]>([]);
  const busy = running !== null;

  const runOne = async (id: string) => {
    const step = WALKTHROUGH.find((s) => s.id === id)!;
    setRunning(id);
    setRuns((r) => ({ ...r, [id]: { state: 'running' } }));
    try {
      const outcome = await step.run();
      setRuns((r) => ({ ...r, [id]: { state: 'done', outcome } }));
    } catch (err) {
      setRuns((r) => ({ ...r, [id]: { state: 'failed', error: (err as Error).message } }));
    } finally {
      setRunning(null);
    }
  };
  const runAll = async () => {
    for (const s of WALKTHROUGH) await runOne(s.id);
  };
  const runDrill = async (name: string) => {
    setRunning(name);
    try {
      const report = await api.runAttack(name);
      setReports((r) => [report, ...r]);
    } catch (err) {
      window.alert(`Could not run: ${(err as Error).message}`);
    } finally {
      setRunning(null);
    }
  };

  return (
    <>
      <Panel
        title="Walkthrough"
        flush
        actions={
          <>
            <span className="small muted">
              Runs against the live gate; nothing is pre-recorded.
            </span>
            <button className="btn-primary btn-sm" disabled={busy} onClick={() => void runAll()}>
              Run all
            </button>
          </>
        }
      >
        <table className="data">
          <thead>
            <tr>
              <th style={{ width: 36 }}>#</th>
              <th>Scenario</th>
              <th>What it proves</th>
              <th>Expected</th>
              <th>Result</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {WALKTHROUGH.map((s, i) => {
              const r = runs[s.id] ?? { state: 'idle' };
              return (
                <tr key={s.id}>
                  <td className="muted">{i + 1}</td>
                  <td>
                    <b>{s.title}</b>
                  </td>
                  <td className="wrap muted">{s.proves}</td>
                  <td>{s.expected}</td>
                  <td className="wrap">
                    {r.state === 'running' && <span className="stamp none">Running…</span>}
                    {r.state === 'failed' && <span className="bad small">{r.error}</span>}
                    {r.state === 'done' && (
                      <>
                        {r.outcome.verdict ? (
                          <Stamp verdict={r.outcome.verdict} />
                        ) : (
                          <span className="stamp ok">{r.outcome.label ?? r.outcome.headline}</span>
                        )}
                        {r.outcome.detail && (
                          <div className="small muted" style={{ marginTop: 4 }}>
                            {r.outcome.detail}
                          </div>
                        )}
                        {r.outcome.releaseId && (
                          <div className="small">
                            <Link to={`/app/releases?r=${r.outcome.releaseId}`}>Open release</Link>
                          </div>
                        )}
                      </>
                    )}
                  </td>
                  <td>
                    <button className="btn-sm" disabled={busy} onClick={() => void runOne(s.id)}>
                      {r.state === 'done' ? 'Run again' : 'Run'}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </Panel>
      <div className="two">
        <Panel title="All drills" flush>
          {drills.error && <p className="notice bad">{drills.error}</p>}
          <table className="data">
            <thead>
              <tr>
                <th>Drill</th>
                <th>Expected</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(drills.data ?? {}).map(([name, spec]) => (
                <tr key={name}>
                  <td>
                    <b>{DRILL_TITLES[name] ?? name}</b>
                    <div className="small muted">{name}</div>
                  </td>
                  <td>{OUTCOME_WORD[spec.expected] ?? spec.expected}</td>
                  <td>
                    <button className="btn-sm" disabled={busy} onClick={() => void runDrill(name)}>
                      {running === name ? 'Running…' : 'Run'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
        <Panel title="Drill results" flush>
          {reports.length === 0 ? (
            <Empty>No drill run yet in this session.</Empty>
          ) : (
            <table className="data">
              <thead>
                <tr>
                  <th>Drill</th>
                  <th>Expected</th>
                  <th>Observed</th>
                  <th>Caught by</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {reports.map((r, i) => (
                  <tr key={`${r.name}-${i}`}>
                    <td>{DRILL_TITLES[r.name] ?? r.name}</td>
                    <td>{OUTCOME_WORD[r.expected] ?? r.expected}</td>
                    <td>{r.observed ? (OUTCOME_WORD[r.observed] ?? r.observed) : '—'}</td>
                    <td className="muted">{r.check?.replace(/_/g, ' ') ?? '—'}</td>
                    <td>
                      <span className={`stamp ${r.passed ? 'ok' : 'bad'}`}>
                        {r.passed ? 'Caught' : 'Missed'}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      </div>
    </>
  );
}
