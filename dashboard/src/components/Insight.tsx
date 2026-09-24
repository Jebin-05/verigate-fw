/** The AI made visible: what the models saw, the written explanation, model cards, rules simulator. */
import { useEffect, useState } from 'react';
import { api } from '../api/client';
import type { ModelCard, Policy, RationaleStatus, Stage2Block } from '../api/types';
import { aiSaw, bp } from '../lib/words';

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
      <p className="hint">
        These are the exact numbers the two models scored; a hash of them is sealed into the
        verdict, so anyone with the model files can recompute the scores.
      </p>
    </section>
  );
}

export function ExplanationBox({
  releaseId,
  hasStage2,
}: {
  releaseId: string;
  hasStage2: boolean;
}) {
  const [status, setStatus] = useState<RationaleStatus | null>(null);
  const [busy, setBusy] = useState(false);
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
  }, [releaseId]);

  const ask = async (again: boolean) => {
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
  };

  let body: React.ReactNode;
  let action: React.ReactNode = null;
  if (!hasStage2) {
    body = (
      <p className="muted small">
        Nothing to explain: the release was stopped by the cryptographic checks before the models
        ran.
      </p>
    );
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
          Suggested action: {status.rationale.recommended_action}. Written by a local language model
          ({status.model}); it reads the verdict, it never writes it.
        </p>
      </div>
    );
    action = (
      <button className="btn-sm" disabled={busy} onClick={() => void ask(true)}>
        Write again
      </button>
    );
  } else if (status.status === 'writing') {
    body = (
      <p className="muted small writing">
        <span className="pulse" /> Writing an explanation — about a minute on a CPU-only laptop. The
        verdict above is already final; the text only describes it.
      </p>
    );
  } else if (status.status === 'off') {
    body = (
      <p className="muted small">
        The explanation model is switched off on this gateway (LLM_ENABLED=false).
      </p>
    );
  } else if (status.status === 'none') {
    body = (
      <p className="muted small">
        {status.reason
          ? `Not available: ${status.reason}.`
          : 'No explanation has been written for this release yet. The local language model reads the recorded scores and the ingredient-list changes and writes a short rationale for a reviewer.'}
      </p>
    );
    if (!status.reason)
      action = (
        <button className="btn-primary" disabled={busy} onClick={() => void ask(false)}>
          {busy ? 'Asking…' : 'Explain this verdict'}
        </button>
      );
  } else {
    body = (
      <p className="muted small">
        The explanation model did not answer{status.reason ? ` (${status.reason})` : ''}. Is Ollama
        running on this computer?
      </p>
    );
    action = (
      <button className="btn-primary" disabled={busy} onClick={() => void ask(true)}>
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
      <p className="small muted">
        Drag the lines. Every verdict in the list is re-computed from its recorded scores — a
        simulation only; the real rules can only change by an administrator’s transaction.
      </p>
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
