/** Approval console: incoming releases, the inspection report for one, the fleet, live activity. */
import { useEffect, useMemo, useState } from 'react';
import { useOutletContext, useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import type {
  Device,
  Health,
  Proof,
  Publisher,
  Rationale,
  Release,
  VerificationResult,
} from '../api/types';
import { verifyLeafOnChain } from '../chain/useChain';
import { Activity } from '../components/Activity';
import { Empty, Id, Meter, Stamp } from '../components/Bits';
import { usePoll } from '../components/usePoll';
import {
  CHECKS,
  VERDICT_TONE,
  VERDICT_WORD,
  bp,
  failureWords,
  fmtDate,
  reasonWords,
  standing,
} from '../lib/words';

const isVerdict = (e: unknown): e is VerificationResult =>
  typeof e === 'object' && e !== null && 'verdict' in e && 'stage1' in e;

export function Approver() {
  const health = useOutletContext<Health | null>();
  const releases = usePoll(api.releases, 3000);
  const verdicts = usePoll(api.verdicts, 3000);
  const devices = usePoll(api.devices, 5000);
  const publishers = usePoll(api.publishers, 15000);
  const policy = usePoll(api.policy, 15000);
  const models = usePoll(api.models, 15000);
  const revocations = usePoll(api.revocations, 15000);

  const list = useMemo(() => (releases.data ?? []).slice().reverse(), [releases.data]);
  const [params] = useSearchParams();
  const [selected, setSelected] = useState<string | null>(params.get('r'));
  useEffect(() => {
    if (!selected && list.length > 0) setSelected(list[0].releaseId);
  }, [list, selected]);
  const release = list.find((r) => r.releaseId === selected) ?? null;

  const publisherName = (id: string) =>
    (publishers.data ?? []).find((p) => p.publisherId === id)?.did.replace('did:verigate:', '') ??
    'unknown publisher';

  return (
    <main className="page wide">
      <div className="page-head">
        <h1>Approval console</h1>
        <p>
          Every release that reaches the gate is listed here with its decision and the reasons
          behind it. Nothing installs on a device without an approval in this list.
        </p>
      </div>
      <div className="console">
        <div>
          <section className="queue">
            <h2>Incoming releases</h2>
            {releases.error && (
              <p className="notice bad">Could not reach the gateway: {releases.error}</p>
            )}
            {list.length === 0 ? (
              <Empty>No releases have been registered yet.</Empty>
            ) : (
              <ul className="rows selectable">
                {list.map((r) => (
                  <li
                    key={r.releaseId}
                    className={r.releaseId === selected ? 'selected' : ''}
                    onClick={() => {
                      setSelected(r.releaseId);
                      document
                        .getElementById('report')
                        ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                    }}
                  >
                    <div>
                      <div className="title">
                        {r.version} <span className="muted">for {r.deviceModel}</span>
                      </div>
                      <div className="sub">
                        from {publisherName(r.publisherId)}
                        {r.lastVerdictAt ? ` · inspected ${fmtDate(r.lastVerdictAt)}` : ''}
                      </div>
                    </div>
                    <Stamp verdict={r.lastVerdict} revoked={r.revoked} />
                  </li>
                ))}
              </ul>
            )}
          </section>
          {release && (
            <Report
              release={release}
              publisher={(publishers.data ?? []).find((p) => p.publisherId === release.publisherId)}
              entries={(verdicts.data ?? [])
                .filter(isVerdict)
                .filter((v) => v.releaseId === release.releaseId)}
              devices={devices.data ?? []}
              health={health}
              policy={policy.data?.policy ?? null}
            />
          )}
        </div>
        <aside className="rail">
          <Activity />
          <FleetSummary devices={devices.data ?? []} releases={releases.data ?? []} />
          <section>
            <h2>Rules in force</h2>
            {policy.data?.policy ? (
              <dl className="kv">
                <dt>Approve below</dt>
                <dd>{bp(policy.data.policy.tau_approve)} overall risk</dd>
                <dt>Review between</dt>
                <dd>
                  {bp(policy.data.policy.tau_approve)} and {bp(policy.data.policy.tau_reject)}
                </dd>
                <dt>Reject from</dt>
                <dd>{bp(policy.data.policy.tau_reject)}</dd>
                <dt>Weights</dt>
                <dd>
                  ingredients {bp(policy.data.policy.w_sbom)} · binary{' '}
                  {bp(policy.data.policy.w_img)} · publisher {bp(policy.data.policy.w_rep)}
                </dd>
              </dl>
            ) : (
              <p className="empty small">Rules unavailable.</p>
            )}
            <p className="hint">
              Changing these is a blockchain transaction by an administrator; the gateway only reads
              them.
            </p>
          </section>
          <section>
            <h2>Inspection models</h2>
            {(models.data ?? []).length === 0 ? (
              <p className="empty small">No models registered.</p>
            ) : (
              <dl className="kv">
                <dt>Current</dt>
                <dd>{(models.data ?? []).filter((m) => m.status === 1).length}</dd>
                <dt>Revoked</dt>
                <dd>{(models.data ?? []).filter((m) => m.status === 2).length}</dd>
              </dl>
            )}
            {(revocations.data ?? []).map((rep) => (
              <p key={rep.modelHash} className="notice warn small">
                A model was revoked on {fmtDate(new Date(rep.startedAt * 1000).toISOString())}:{' '}
                {rep.pairs.length} earlier verdicts were re-checked
                {rep.swapped
                  ? ' with its successor'
                  : ' without a successor (all now rejected)'}; {rep.changed} changed.
              </p>
            ))}
          </section>
        </aside>
      </div>
    </main>
  );
}

function FleetSummary({ devices, releases }: { devices: Device[]; releases: Release[] }) {
  const byVersion = new Map<string, number>();
  for (const d of devices)
    byVersion.set(d.installed_version, (byVersion.get(d.installed_version) ?? 0) + 1);
  const versions = Array.from(byVersion.entries()).sort((a, b) => b[1] - a[1]);
  const latest = releases.filter((r) => r.lastVerdict === 'APPROVE' && !r.revoked).at(-1);
  return (
    <section>
      <h2>Your devices</h2>
      {devices.length === 0 ? (
        <p className="empty small">No device has checked in yet.</p>
      ) : (
        <dl className="kv">
          <dt>Checked in</dt>
          <dd>{devices.length}</dd>
          <dt>Running</dt>
          <dd>
            {versions.map(([v, n]) => (
              <div key={v}>
                {v} on {n} device{n === 1 ? '' : 's'}
              </div>
            ))}
          </dd>
          {latest && (
            <>
              <dt>Latest approved</dt>
              <dd>{latest.version}</dd>
            </>
          )}
        </dl>
      )}
    </section>
  );
}

function Report({
  release,
  publisher,
  entries,
  devices,
  health,
  policy,
}: {
  release: Release;
  publisher: Publisher | undefined;
  entries: VerificationResult[];
  devices: Device[];
  health: Health | null;
  policy: { tau_approve: number; tau_reject: number } | null;
}) {
  const fleetLevel =
    entries.filter((e) => e.deviceId === 'release-level').at(-1) ?? entries.at(-1) ?? null;
  const perDevice = new Map<string, VerificationResult>();
  for (const e of entries) if (e.deviceId !== 'release-level') perDevice.set(e.deviceId, e);
  const deviceCounts = { APPROVE: 0, DEFER: 0, REJECT: 0 };
  for (const v of perDevice.values()) deviceCounts[v.verdict] += 1;
  const installed = devices.filter((d) => d.installed_release_id === release.releaseId).length;

  const [rationale, setRationale] = useState<Rationale | null>(null);
  const [proof, setProof] = useState<{ p: Proof; onChain: boolean | null } | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setRationale(null);
    setProof(null);
    if (fleetLevel?.rationaleCid) {
      api
        .rationale(fleetLevel.rationaleCid)
        .then(setRationale)
        .catch(() => setRationale(null));
    }
  }, [fleetLevel?.rationaleCid, release.releaseId]);

  const checkOnChain = async () => {
    if (!fleetLevel?.verdictId) return;
    setBusy(true);
    try {
      const p = await api.proof(fleetLevel.verdictId);
      let onChain: boolean | null = null;
      if (p.status === 'committed' && health?.contracts && p.batchId !== undefined && p.proof) {
        onChain = await verifyLeafOnChain(
          health.contracts.VerdictRegistry,
          p.batchId,
          p.verdictId,
          p.proof,
        );
      }
      setProof({ p, onChain });
    } catch (err) {
      window.alert(`Could not fetch the proof: ${(err as Error).message}`);
    } finally {
      setBusy(false);
    }
  };

  const stand = standing(fleetLevel?.reputation ?? publisher?.reputation);
  const stage1 = fleetLevel?.stage1 ?? null;
  const ran = new Map(stage1?.checks.map((c) => [c.name, c]) ?? []);
  const marks = policy
    ? [
        { at: policy.tau_approve, label: 'approve' },
        { at: policy.tau_reject, label: 'reject' },
      ]
    : [];

  return (
    <article className="report" id="report" aria-live="polite">
      <div className="report-head">
        <div>
          <h2>
            Inspection report — {release.version} for {release.deviceModel}
          </h2>
          <p className="muted small">
            From {publisher?.did.replace('did:verigate:', '') ?? 'unknown publisher'} · publisher
            standing <b className={stand.tone}>{stand.label}</b>
            {fleetLevel ? ` · inspected ${fmtDate(fleetLevel.checkedAt)}` : ''}
          </p>
          {release.revoked ? (
            <p className="lede">The publisher has withdrawn this release. Devices refuse it.</p>
          ) : fleetLevel ? (
            <p className="lede">{reasonWords(fleetLevel)}</p>
          ) : (
            <p className="lede">
              Not inspected yet — the gateway picks up new releases within a few seconds.
            </p>
          )}
        </div>
        <Stamp verdict={fleetLevel?.verdict ?? release.lastVerdict} revoked={release.revoked} big />
      </div>

      <section>
        <h3>The eight checks</h3>
        <ul className="checks">
          {CHECKS.map((c) => {
            const r = ran.get(c.name);
            const cls = !r ? 'skipped' : r.ok ? 'pass' : 'fail';
            return (
              <li key={c.name} className={cls}>
                <span aria-hidden="true">{!r ? '·' : r.ok ? '✓' : '✕'}</span>
                <span>
                  {c.text}
                  {r && !r.ok && <span className="why">{failureWords(c.name, r.reason)}</span>}
                  {!r && stage1 && (
                    <span className="why">not reached — an earlier check failed</span>
                  )}
                </span>
              </li>
            );
          })}
        </ul>
      </section>

      {fleetLevel && stage1?.ok && (
        <section>
          <h3>Risk scoring</h3>
          <div className="meters">
            <Meter
              label="Known-vulnerability exposure"
              value={fleetLevel.rSbom}
              tone={toneFor(fleetLevel.rSbom)}
            />
            <Meter
              label="Unusual structure in the binary"
              value={fleetLevel.rImg}
              tone={toneFor(fleetLevel.rImg)}
            />
            <Meter
              label="Publisher standing, as risk"
              value={fleetLevel.reputation === null ? null : 10000 - fleetLevel.reputation}
              tone={toneFor(fleetLevel.reputation === null ? null : 10000 - fleetLevel.reputation)}
            />
            <Meter
              label="Overall risk"
              value={fleetLevel.R}
              tone={VERDICT_TONE[fleetLevel.verdict]}
              marks={marks}
              overall
            />
          </div>
          <p className="hint" style={{ marginTop: 26 }}>
            Scores run from 0 (no concern) to 1. The overall risk is a weighted mix of the three,
            compared with the approve and reject lines set by the administrator.
          </p>
        </section>
      )}

      <section>
        <h3>Explanation</h3>
        {rationale ? (
          <div className="rationale">
            <p>{rationale.summary}</p>
            {rationale.top_risks.length > 0 && (
              <ul>
                {rationale.top_risks.map((r) => (
                  <li key={r}>{r}</li>
                ))}
              </ul>
            )}
            <p className="small muted" style={{ marginTop: 8 }}>
              Suggested action: {rationale.recommended_action}. Written by the explanation model; it
              never influences the decision above.
            </p>
          </div>
        ) : (
          <p className="muted small">
            No written explanation for this verdict
            {fleetLevel?.rationaleCid ? ' (loading)' : ' — the explanation model is switched off'}.
          </p>
        )}
      </section>

      <section>
        <h3>Devices</h3>
        <div className="counts">
          <div>
            <div className="n">{installed}</div>
            <div className="l">installed it</div>
          </div>
          {(['APPROVE', 'DEFER', 'REJECT'] as const).map((k) => (
            <div key={k}>
              <div className="n">{deviceCounts[k]}</div>
              <div className="l">{VERDICT_WORD[k].toLowerCase()} for a device</div>
            </div>
          ))}
        </div>
      </section>

      <section>
        <h3>Proof</h3>
        {fleetLevel?.verdictId ? (
          <>
            <p className="small muted">
              This decision was signed by the gateway and anchored on the blockchain in a batch. You
              can check that yourself, straight from the chain.
            </p>
            <p style={{ marginTop: 10 }}>
              <button onClick={() => void checkOnChain()} disabled={busy}>
                {busy ? 'Checking…' : 'Verify on the blockchain'}
              </button>
            </p>
            {proof && (
              <p
                className={`notice ${proof.p.status === 'pending' ? 'warn' : proof.onChain ? 'ok' : 'bad'}`}
              >
                {proof.p.status === 'pending'
                  ? 'Not anchored yet — it goes on-chain with the next batch (within seconds).'
                  : proof.onChain
                    ? `Verified: batch ${proof.p.batchId}, block ${proof.p.blockNumber}. The blockchain confirms this exact decision.`
                    : 'The chain did not confirm this proof.'}
              </p>
            )}
          </>
        ) : (
          <p className="muted small">No anchored decision yet.</p>
        )}
        <details className="tech">
          <summary>Technical identifiers</summary>
          <dl>
            <dt>Release</dt>
            <dd>
              <Id value={release.releaseId} chars={16} />
            </dd>
            <dt>Decision</dt>
            <dd>
              <Id value={fleetLevel?.verdictId} chars={16} />
            </dd>
            {stage1 && !stage1.ok && (
              <>
                <dt>Failure detail</dt>
                <dd>{stage1.reason}</dd>
              </>
            )}
            <dt>Models</dt>
            <dd>
              {(fleetLevel?.modelHashes ?? []).map((h) => (
                <div key={h}>
                  <Id value={h} chars={16} />
                </div>
              ))}
              {(fleetLevel?.modelHashes ?? []).length === 0 && '—'}
            </dd>
          </dl>
        </details>
      </section>
    </article>
  );
}

function toneFor(bpValue: number | null | undefined): 'ok' | 'warn' | 'bad' | 'none' {
  if (bpValue === null || bpValue === undefined) return 'none';
  if (bpValue < 4500) return 'ok';
  if (bpValue < 7000) return 'warn';
  return 'bad';
}
