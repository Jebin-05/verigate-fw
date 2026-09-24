/** Guided demonstration: seven scenarios, one Run button each, with narration and live results. */
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../api/client';
import type { AttackReport, Release, Verdict } from '../api/types';
import { Stamp } from '../components/Bits';
import { checkText, failureWords, VERDICT_WORD } from '../lib/words';

interface Outcome {
  headline: string;
  verdict?: Verdict | null;
  outcome?: string; // for the flow drills: Blocked / Re-checked
  detail?: string;
  releaseId?: string | null;
}

interface Step {
  id: string;
  title: string;
  say: string;
  watch: string;
  run: () => Promise<Outcome>;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitForVerdict(releaseId: string, timeoutMs = 45000): Promise<Release | null> {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    const r = (await api.releases()).find((x) => x.releaseId === releaseId);
    if (r?.lastVerdict) return r;
    await sleep(1500);
  }
  return null;
}

function fromAttack(report: AttackReport): Outcome {
  const verdict =
    (['APPROVE', 'DEFER', 'REJECT'] as const).find((v) => v === report.observed) ?? null;
  const detail = report.check
    ? `Caught by “${checkText(report.check)}”. ${failureWords(report.check, report.reason)}`
    : (report.reason ?? undefined);
  return {
    headline: verdict ? VERDICT_WORD[verdict] : (report.observed ?? 'no result'),
    verdict,
    outcome: verdict ? undefined : (report.observed ?? undefined),
    detail,
    releaseId: report.release_id,
  };
}

const STEPS: Step[] = [
  {
    id: 'genuine',
    title: 'A genuine release',
    say: 'The maker publishes firmware. Every release is signed, put on the blockchain and inspected before any device sees it.',
    watch:
      'The stamp arrives within seconds. Open the report: eight green checks and the AI’s risk meters.',
    run: async () => {
      const r = await api.storyPublish('v2.0.0');
      const rel = await waitForVerdict(r.releaseId);
      return {
        headline: rel?.lastVerdict ? VERDICT_WORD[rel.lastVerdict] : 'Inspection pending',
        verdict: rel?.lastVerdict ?? null,
        detail: `Version ${r.version} — a real OpenWrt 24.10 build with its real ingredient list.`,
        releaseId: r.releaseId,
      };
    },
  },
  {
    id: 'tamper',
    title: 'Someone tampers with the file',
    say: 'The file behind the download link is swapped after it was signed.',
    watch:
      'Rejected in under a second — by cryptography, before the AI is even consulted. One red check.',
    run: async () => fromAttack(await api.runAttack('tamper')),
  },
  {
    id: 'vulnerable',
    title: 'Honest, but old software',
    say: 'Nothing is forged. The maker simply ships a 2019 base with 72 known vulnerabilities.',
    watch:
      'Needs review — this is the AI’s job. Open the report: “What the AI saw” lists the vulnerability counts that drove the score.',
    run: async () => fromAttack(await api.runAttack('vulnerable-genuine')),
  },
  {
    id: 'payload',
    title: 'A hidden payload',
    say: 'A real build with 200 KB of packed code appended after the end of the image.',
    watch:
      'Needs review — the binary model’s meter jumps; the report shows the bytes after the declared end.',
    run: async () => fromAttack(await api.runAttack('hidden-payload')),
  },
  {
    id: 'rules',
    title: 'What if the rules were stricter?',
    say: 'The rules live on the blockchain. A person cannot quietly loosen them — and you can see what stricter rules would do.',
    watch:
      'In the console, drag the reject line down: step 3’s release flips to Rejected, live, labelled as a simulation. Then run this: a rogue operator tries to change the real rules.',
    run: async () => fromAttack(await api.runAttack('policy-tamper')),
  },
  {
    id: 'model',
    title: 'The AI itself can be wrong',
    say: 'No prior system does this: an inspection model is revoked like a bad key, and every verdict it produced is re-checked with its successor.',
    watch:
      'The Models panel in the console shows how many verdicts were re-checked and how many changed.',
    run: async () => {
      const report = await api.runAttack('poisoned-model');
      const d = report.details as Record<string, unknown>;
      return {
        headline: report.passed ? 'Re-checked' : 'Not re-checked',
        outcome: report.observed ?? undefined,
        detail: `${String(d.pairsReplayed ?? 0)} earlier verdicts replayed${d.mode === 'swap-to-successor' ? ' with the successor model' : ' — no successor left, so the gate now fails closed'}; ${String(d.changed ?? 0)} changed.`,
        releaseId: report.release_id,
      };
    },
  },
  {
    id: 'device',
    title: 'The devices',
    say: 'Meanwhile the locks themselves: a device asks, checks the answer itself, installs, and signs a receipt.',
    watch:
      'One emulated device runs a full cycle; the publisher portal’s “installed on N devices” ticks up.',
    run: async () => {
      const s = await api.simulateDevice();
      const verdicts = Object.values(s.lastVerdicts ?? {});
      return {
        headline:
          s.installs > 0
            ? 'Installed'
            : verdicts[0]
              ? VERDICT_WORD[verdicts[0] as Verdict]
              : 'No update',
        verdict: s.installs > 0 ? 'APPROVE' : ((verdicts[0] as Verdict) ?? null),
        detail: `${s.polls} poll, ${s.installs} install, ${s.receipts} signed receipt${s.rejected ? `, ${s.rejected} refused` : ''}.`,
      };
    },
  },
];

type Run =
  | { state: 'idle' }
  | { state: 'running' }
  | { state: 'done'; outcome: Outcome }
  | { state: 'failed'; error: string };

export function Story() {
  const [runs, setRuns] = useState<Record<string, Run>>({});
  const busy = Object.values(runs).some((r) => r.state === 'running');

  const run = async (step: Step) => {
    setRuns((r) => ({ ...r, [step.id]: { state: 'running' } }));
    try {
      const outcome = await step.run();
      setRuns((r) => ({ ...r, [step.id]: { state: 'done', outcome } }));
    } catch (err) {
      setRuns((r) => ({ ...r, [step.id]: { state: 'failed', error: (err as Error).message } }));
    }
  };

  return (
    <main className="page narrow">
      <div className="page-head">
        <h1>Present to a panel</h1>
        <p className="reading">
          Seven scenarios, in the order that tells the story. Read the line, press Run, and the
          result arrives live from the real gate — nothing here is pre-recorded. Keep the{' '}
          <Link to="/approve" target="_blank" rel="noreferrer">
            approval console
          </Link>{' '}
          open in a second window to show the full report.
        </p>
      </div>
      <details className="tech" style={{ marginBottom: 18 }}>
        <summary>Before the panel (two minutes)</summary>
        <ul>
          <li>
            Run this page once the day before: the first inspection fills the vulnerability cache.
          </li>
          <li>
            Start Ollama if you want the written explanations (they take about a minute each).
          </li>
          <li>Step 6 can run twice per fresh chain — once with a successor, once without.</li>
        </ul>
      </details>
      <ol className="steps">
        {STEPS.map((step, i) => {
          const r = runs[step.id] ?? { state: 'idle' };
          return (
            <li key={step.id} className={`step ${r.state}`}>
              <div className="step-n">{i + 1}</div>
              <div className="step-body">
                <h2>{step.title}</h2>
                <p className="reading say">“{step.say}”</p>
                <p className="small muted">What to watch for: {step.watch}</p>
                <div className="step-actions">
                  <button className="primary" disabled={busy} onClick={() => void run(step)}>
                    {r.state === 'running' ? 'Running…' : r.state === 'done' ? 'Run again' : 'Run'}
                  </button>
                  {step.id === 'rules' && (
                    <Link to="/approve" target="_blank" rel="noreferrer" className="button">
                      Open the sliders in the console
                    </Link>
                  )}
                </div>
                {r.state === 'failed' && <p className="notice bad">Could not run: {r.error}</p>}
                {r.state === 'done' && (
                  <div className="result">
                    {r.outcome.verdict !== undefined || r.outcome.outcome ? (
                      r.outcome.verdict ? (
                        <Stamp verdict={r.outcome.verdict} big />
                      ) : (
                        <span className="stamp ok big">
                          {r.outcome.outcome ?? r.outcome.headline}
                        </span>
                      )
                    ) : (
                      <span className="stamp none big">{r.outcome.headline}</span>
                    )}
                    <div>
                      {r.outcome.detail && <p className="reading">{r.outcome.detail}</p>}
                      {r.outcome.releaseId && (
                        <p>
                          <Link
                            to={`/approve?r=${r.outcome.releaseId}`}
                            target="_blank"
                            rel="noreferrer"
                          >
                            Open the inspection report
                          </Link>
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </li>
          );
        })}
      </ol>
      <p className="small muted" style={{ marginTop: 26 }}>
        Close with the report’s <b>Verify on the blockchain</b> button: the decision you just
        watched is checked against the chain in front of the panel.
      </p>
    </main>
  );
}
