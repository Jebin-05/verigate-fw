/** The AI made visible: what the models saw, the written explanation, model cards, rules simulator. */
import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from '../api/client';
import type { AiAnalysis, ModelCard, Policy, RationaleStatus, Stage2Block } from '../api/types';
import { aiSaw, bp, VERDICT_TONE, VERDICT_WORD, type Tone } from '../lib/words';
import { Meter } from './Bits';

export function AiSaw({ stage2 }: { stage2: Stage2Block | null | undefined }) {
  const seen = aiSaw(stage2);
  if (!seen) return null;
  return (
    <section>
      <h3>What the AI saw</h3>
      <div className="saw">
        <div>
          <h4>Ingredient list</h4>
          <ul>
            {seen.sbom.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
          {seen.sbomDrivers.length > 0 && (
            <p className="drivers">Biggest influences: {seen.sbomDrivers.join('; ')}.</p>
          )}
        </div>
        <div>
          <h4>The binary itself</h4>
          <ul>
            {seen.img.map((t) => (
              <li key={t}>{t}</li>
            ))}
          </ul>
          {seen.imgDrivers.length > 0 && (
            <p className="drivers">Biggest influences: {seen.imgDrivers.join('; ')}.</p>
          )}
        </div>
      </div>
    </section>
  );
}

const riskTone = (v: number | null | undefined): Tone =>
  v === null || v === undefined ? 'none' : v < 4500 ? 'ok' : v < 7000 ? 'warn' : 'bad';

/**
 * The AI tab, shown only on request. ``recorded`` (a release that reached the models): the button
 * reveals what the models saw when the gate decided. Otherwise the button runs the models now.
 */
export function AiRun({
  releaseId,
  marks,
  recorded,
  onRun,
}: {
  releaseId: string;
  marks: { at: number; label: string }[];
  recorded?: Stage2Block | null;
  onRun?: () => void;
}) {
  const [result, setResult] = useState<AiAnalysis | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    setResult(null);
    setError(null);
  }, [releaseId]);

  const run = async () => {
    if (recorded) {
      setResult({ status: 'ready', stage2: recorded });
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const a = await api.analyse(releaseId);
      setResult(a);
      if (a.status === 'ready') onRun?.();
      else setError(a.reason ?? 'the models could not run');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const ready = result?.status === 'ready';
  return (
    <section>
      <div className="detail-h">
        <h3>AI risk analysis</h3>
        {!(recorded && ready) && (
          <button
            className={ready ? 'btn-sm' : 'btn-primary'}
            disabled={busy}
            onClick={() => void run()}
          >
            {busy
              ? 'Running…'
              : ready
                ? 'Run again'
                : recorded
                  ? 'Show AI analysis'
                  : 'Run AI analysis'}
          </button>
        )}
      </div>
      {error && <p className="muted small">Could not run: {error}.</p>}
      {!ready && !error && !recorded && (
        <p className="muted small">
          The risk models did not run: the release was stopped by the checks.
        </p>
      )}
      {ready && recorded && <AiSaw stage2={result.stage2} />}
      {ready && !recorded && (
        <>
          <div className="meters">
            <Meter
              label="Known-vulnerability exposure"
              value={result.rSbom}
              tone={riskTone(result.rSbom)}
            />
            <Meter
              label="Unusual binary structure"
              value={result.rImg}
              tone={riskTone(result.rImg)}
            />
            <Meter
              label="Overall risk"
              value={result.R}
              tone={result.verdictFromScores ? VERDICT_TONE[result.verdictFromScores] : 'none'}
              marks={marks}
              overall
            />
          </div>
          {result.verdictFromScores && (
            <p className="small">
              The scores alone point to{' '}
              <b>{VERDICT_WORD[result.verdictFromScores].toLowerCase()}</b>; the failed check
              decides this release.
            </p>
          )}
          <AiSaw stage2={result.stage2} />
        </>
      )}
    </section>
  );
}

export function ExplanationBox({
  releaseId,
  inspected,
  ask = 0,
  refresh = 0,
  onStatus,
}: {
  releaseId: string;
  /** The gate has a verdict for this release (approved, held or rejected — by the checks or the models). */
  inspected: boolean;
  /** Bumped by the header's "Explain with AI" button: start writing unless one exists already. */
  ask?: number;
  /** Bumped when something the explanation depends on changed (e.g. an AI analysis ran). */
  refresh?: number;
  /** Lets the parent mirror the state (e.g. disable its own button while writing). */
  onStatus?: (status: RationaleStatus['status'] | null) => void;
}) {
  const [status, setStatus] = useState<RationaleStatus | null>(null);
  useEffect(() => {
    onStatus?.(status?.status ?? null);
  }, [status, onStatus]);
  const [busy, setBusy] = useState(false);
  const askedAt = useRef(0);
  useEffect(() => {
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const tick = async () => {
      try {
        const s = await api.rationaleStatus(releaseId);
        if (!alive) return;
        setStatus(s);
        if (s.status === 'writing') timer = setTimeout(() => void tick(), 3000);
      } catch {
        if (alive) setStatus({ status: 'failed' });
      }
    };
    setStatus(null);
    void tick();
    return () => {
      alive = false;
      if (timer) clearTimeout(timer);
    };
  }, [releaseId, refresh]);

  const request = useCallback(
    async (again: boolean) => {
      setBusy(true);
      try {
        const s = await api.explain(releaseId, again);
        setStatus(s);
        if (s.status === 'writing') {
          const poll = async () => {
            const next = await api.rationaleStatus(releaseId);
            setStatus(next);
            if (next.status === 'writing') setTimeout(() => void poll(), 3000);
          };
          setTimeout(() => void poll(), 3000);
        }
      } catch (err) {
        setStatus({ status: 'failed', reason: (err as Error).message });
      } finally {
        setBusy(false);
      }
    },
    [releaseId],
  );
  useEffect(() => {
    // The header button: write once per press, but never discard an explanation that exists.
    if (ask === 0 || ask === askedAt.current || !status || !inspected) return;
    askedAt.current = ask;
    if (status.status === 'none' || status.status === 'failed')
      void request(status.status === 'failed');
  }, [ask, status, inspected, request]);

  let body: React.ReactNode;
  let action: React.ReactNode = null;
  if (!inspected) {
    body = <p className="muted small">Not inspected yet.</p>;
  } else if (!status) {
    body = <p className="muted small">Checking…</p>;
  } else if (status.status === 'ready' && status.rationale) {
    body = (
      <div className="rationale">
        <p>{status.rationale.summary}</p>
        {status.rationale.top_risks.length > 0 && (
          <ul>
            {status.rationale.top_risks.map((r) => (
              <li key={r}>{r.replace(/_/g, ' ')}</li>
            ))}
          </ul>
        )}
        <p className="small muted" style={{ marginTop: 8 }}>
          Recommended action: {status.rationale.recommended_action} · generated by {status.model}
        </p>
      </div>
    );
    action = (
      <button className="btn-sm" disabled={busy} onClick={() => void request(true)}>
        Write again
      </button>
    );
  } else if (status.status === 'writing') {
    body = (
      <p className="muted small writing">
        <span className="pulse" /> Writing the explanation…
      </p>
    );
  } else if (status.status === 'off') {
    body = <p className="muted small">Explanations are switched off on this gateway.</p>;
  } else if (status.status === 'none') {
    body = (
      <p className="muted small">
        {status.reason
          ? `Not available: ${status.reason}.`
          : 'No explanation has been written for this release yet.'}
      </p>
    );
    if (!status.reason)
      action = (
        <button className="btn-primary" disabled={busy} onClick={() => void request(false)}>
          {busy ? 'Asking…' : 'Explain this verdict'}
        </button>
      );
  } else {
    body = (
      <p className="muted small">
        The explanation model did not answer{status.reason ? ` (${status.reason})` : ''}. Try again
        in a moment.
      </p>
    );
    action = (
      <button className="btn-primary" disabled={busy} onClick={() => void request(true)}>
        {busy ? 'Asking…' : 'Try again'}
      </button>
    );
  }
  return (
    <section>
      <div className="row-between">
        <h3>Explanation</h3>
        {action}
      </div>
      {body}
    </section>
  );
}

export function ModelCards() {
  const [cards, setCards] = useState<ModelCard[]>([]);
  useEffect(() => {
    api
      .modelCards()
      .then(setCards)
      .catch(() => setCards([]));
  }, []);
  if (cards.length === 0) return null;
  return (
    <section>
      <h2>How the models were built</h2>
      {cards.map((c) => (
        <details key={c.modelHash} className="card">
          <summary>
            <b>
              {c.name === 'sbom_risk'
                ? 'Ingredient-list model'
                : c.name === 'image_anomaly'
                  ? 'Binary-structure model'
                  : c.name}
            </b>
          </summary>
          <p className="small">{cardSummary(c)}</p>
          {c.card && (
            <details className="tech">
              <summary>Full model card</summary>
              <pre>{c.card}</pre>
            </details>
          )}
        </details>
      ))}
    </section>
  );
}

function num(v: unknown, digits = 2): string {
  return typeof v === 'number' ? v.toFixed(digits) : '—';
}

function cardSummary(c: ModelCard): string {
  const m = (c.metrics ?? {}) as Record<string, unknown>;
  if (c.name === 'sbom_risk') {
    const mm = (m.metrics ?? {}) as Record<string, Record<string, number>>;
    return `Trained on ${String(m.rows ?? '?')} real OpenWrt releases (${String(m.train_rows ?? '?')} to learn from, ${String(m.test_rows ?? '?')} held back for testing). It predicts how many of a release’s known vulnerabilities will actually be exploited. On the held-back releases its error is ${num(mm.model?.mae)} expected exploits, against ${num(mm.baseline?.mae)} for a plain severity formula. Known blind spot: none of the training corpus appears on the government’s known-exploited list, so that signal is untested.`;
  }
  if (c.name === 'image_anomaly') {
    const mm = (m.metrics ?? {}) as Record<string, Record<string, number>>;
    return `Trained only on ${String(m.benign ?? '?')} genuine firmware binaries, then tested against ${String(m.tampered ?? '?')} deliberately tampered copies. It catches appended payloads almost every time (recall ${num(mm.append?.recall)}) and partly catches packing (${num(mm.pack?.recall)}), but rarely catches small byte patches (${num(mm['byte-patch']?.recall)}) — which is exactly why the cryptographic checks run first and cannot be overridden.`;
  }
  return c.file;
}

export function RulesSimulator({
  policy,
  sim,
  setSim,
  changed,
}: {
  policy: Policy | null;
  sim: { approve: number; reject: number } | null;
  setSim: (s: { approve: number; reject: number } | null) => void;
  changed: number;
}) {
  if (!policy) return null;
  const a = sim?.approve ?? policy.tau_approve;
  const r = sim?.reject ?? policy.tau_reject;
  const update = (na: number, nr: number) => {
    const approve = Math.min(na, nr - 100);
    setSim(
      approve === policy.tau_approve && nr === policy.tau_reject ? null : { approve, reject: nr },
    );
  };
  return (
    <section className="sim">
      <h2>What if the rules changed?</h2>
      <p className="small muted">Simulation only. The rules in force do not change.</p>
      <label>
        Approve below <b>{bp(a)}</b>
        <input
          type="range"
          min={0}
          max={10000}
          step={100}
          value={a}
          onChange={(e) => update(Number(e.target.value), r)}
        />
      </label>
      <label>
        Reject from <b>{bp(r)}</b>
        <input
          type="range"
          min={100}
          max={10000}
          step={100}
          value={r}
          onChange={(e) => update(a, Number(e.target.value))}
        />
      </label>
      {sim ? (
        <p className="notice warn small">
          Simulation on: {changed} verdict{changed === 1 ? '' : 's'} would change.{' '}
          <button className="link-button" onClick={() => setSim(null)}>
            Back to the real rules
          </button>
        </p>
      ) : (
        <p className="hint">Showing the rules in force.</p>
      )}
    </section>
  );
}
