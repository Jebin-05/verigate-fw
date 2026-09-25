/** Releases: filterable table on the left, the selected release's inspection detail on the right. */
import { useCallback, useEffect, useMemo, useState, type KeyboardEvent } from 'react';
import { useOutletContext, useSearchParams } from 'react-router-dom';
import { api } from '../../api/client';
import type {
  Device,
  Health,
  Policy,
  Proof,
  Publisher,
  Release,
  VerificationResult,
} from '../../api/types';
import { verifyLeafOnChain } from '../../chain/useChain';
import { Empty, Id, Loading, Meter, Panel, Stamp, Tabs, Time } from '../../components/Bits';
import { AiSaw, ExplanationBox } from '../../components/Insight';
import { usePoll } from '../../components/usePoll';
import { useSim, useToast } from '../../state/store';
import {
  CHECKS,
  VERDICT_TONE,
  VERDICT_WORD,
  bp,
  failureWords,
  fmtDate,
  isVerdict,
  reasonWords,
  simulate,
  standing,
} from '../../lib/words';

type Filter = 'all' | 'APPROVE' | 'DEFER' | 'REJECT' | 'withdrawn';
const FILTERS: Filter[] = ['all', 'APPROVE', 'DEFER', 'REJECT', 'withdrawn'];

export function Releases() {
  const health = useOutletContext<Health | null>();
  const releases = usePoll(api.releases, 3000);
  const verdicts = usePoll(api.verdicts, 3000);
  const devices = usePoll(api.devices, 5000);
  const publishers = usePoll(api.publishers, 15000);
  const policy = usePoll(api.policy, 15000);
  const { sim } = useSim();

  const fleetByRelease = useMemo(() => {
    const m = new Map<string, VerificationResult>();
    for (const e of (verdicts.data ?? []).filter(isVerdict))
      if (e.deviceId === 'release-level') m.set(e.releaseId, e);
    return m;
  }, [verdicts.data]);
  const pubName = (id: string) =>
    (publishers.data ?? []).find((p) => p.publisherId === id)?.did.replace('did:verigate:', '') ??
    '—';

  // Search, filter, selection and tab all live in the URL so links and the back button work.
  const [params, setParams] = useSearchParams();
  const query = params.get('q') ?? '';
  const filter = (FILTERS.includes(params.get('f') as Filter) ? params.get('f') : 'all') as Filter;
  const patch = useCallback(
    (next: Record<string, string | null>, replace = false) => {
      setParams(
        (prev) => {
          const p = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(next)) {
            if (v === null || v === '' || (k === 'f' && v === 'all')) p.delete(k);
            else p.set(k, v);
          }
          return p;
        },
        { replace },
      );
    },
    [setParams],
  );
  const list = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (releases.data ?? [])
      .slice()
      .reverse()
      .filter((r) => {
        if (filter === 'withdrawn' && !r.revoked) return false;
        if (filter !== 'all' && filter !== 'withdrawn' && (r.revoked || r.lastVerdict !== filter))
          return false;
        if (!q) return true;
        return `${r.version} ${r.deviceModel} ${pubName(r.publisherId)} ${r.releaseId}`
          .toLowerCase()
          .includes(q);
      });
  }, [releases.data, query, filter, publishers.data]); // eslint-disable-line react-hooks/exhaustive-deps

  const selected = params.get('r');
  useEffect(() => {
    if (!selected && list.length > 0) patch({ r: list[0].releaseId }, true);
  }, [list, selected, patch]);
  const release = (releases.data ?? []).find((r) => r.releaseId === selected) ?? null;
  const select = (id: string) => patch({ r: id, tab: null });
  const onRowKey = (e: KeyboardEvent<HTMLTableRowElement>, index: number) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      select(list[index].releaseId);
    } else if (e.key === 'ArrowDown' && index < list.length - 1) {
      e.preventDefault();
      select(list[index + 1].releaseId);
      (e.currentTarget.nextElementSibling as HTMLElement | null)?.focus();
    } else if (e.key === 'ArrowUp' && index > 0) {
      e.preventDefault();
      select(list[index - 1].releaseId);
      (e.currentTarget.previousElementSibling as HTMLElement | null)?.focus();
    }
  };

  return (
    <div className="split">
      <Panel
        title={`Releases (${list.length})`}
        flush
        actions={
          <>
            <input
              type="search"
              placeholder="Search version, model, publisher…"
              value={query}
              onChange={(e) => patch({ q: e.target.value }, true)}
              aria-label="Search releases"
            />
            <select
              value={filter}
              onChange={(e) => patch({ f: e.target.value })}
              aria-label="Filter by verdict"
            >
              <option value="all">All</option>
              <option value="APPROVE">Approved</option>
              <option value="DEFER">Needs review</option>
              <option value="REJECT">Rejected</option>
              <option value="withdrawn">Withdrawn</option>
            </select>
          </>
        }
      >
        {sim && (
          <p className="notice warn" style={{ margin: 10 }}>
            Simulation on: verdicts shown under approve &lt; {bp(sim.approve)}, reject ≥{' '}
            {bp(sim.reject)}. Change or clear it under Governance.
          </p>
        )}
        {releases.error && <p className="notice bad">{releases.error}</p>}
        {releases.loading ? (
          <Loading what="releases" />
        ) : list.length === 0 ? (
          <Empty>
            {(releases.data ?? []).length === 0 ? (
              'No releases registered yet.'
            ) : (
              <>
                No releases match.{' '}
                <button className="link-button" onClick={() => patch({ q: null, f: null })}>
                  Clear the search and filter
                </button>
              </>
            )}
          </Empty>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Version</th>
                <th>Model</th>
                <th>Publisher</th>
                <th>Verdict</th>
                <th className="num">Risk</th>
                <th>Inspected</th>
                <th className="num">Installed</th>
              </tr>
            </thead>
            <tbody>
              {list.map((r, i) => {
                const f = fleetByRelease.get(r.releaseId);
                const simulated =
                  sim && f ? simulate(f.verdict, f.stage1?.ok ?? null, f.R, sim) : null;
                const installed = (devices.data ?? []).filter(
                  (d) => d.installed_release_id === r.releaseId,
                ).length;
                return (
                  <tr
                    key={r.releaseId}
                    className={`clickable${r.releaseId === selected ? ' selected' : ''}`}
                    onClick={() => select(r.releaseId)}
                    onKeyDown={(e) => onRowKey(e, i)}
                    tabIndex={0}
                    aria-selected={r.releaseId === selected}
                  >
                    <td>
                      <b>{r.version}</b>
                    </td>
                    <td>{r.deviceModel}</td>
                    <td>{pubName(r.publisherId)}</td>
                    <td>
                      <Stamp verdict={simulated ?? r.lastVerdict} revoked={r.revoked} />
                      {simulated && f && simulated !== f.verdict && (
                        <span className="simulated">really {VERDICT_WORD[f.verdict]}</span>
                      )}
                    </td>
                    <td className="num">{f && f.stage1?.ok ? bp(f.R) : '—'}</td>
                    <td className="muted">
                      <Time iso={r.lastVerdictAt} />
                    </td>
                    <td className="num">{installed}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Panel>
      <div className="detail">
        {release ? (
          <Detail
            release={release}
            publisher={(publishers.data ?? []).find((p) => p.publisherId === release.publisherId)}
            entries={(verdicts.data ?? [])
              .filter(isVerdict)
              .filter((v) => v.releaseId === release.releaseId)}
            devices={devices.data ?? []}
            health={health}
            policy={policy.data?.policy ?? null}
            initialTab={
              TABS.includes(params.get('tab') as Tab) ? (params.get('tab') as Tab) : undefined
            }
            onTab={(t) => patch({ tab: t }, true)}
          />
        ) : (
          <Panel>
            <Empty>Select a release to see its inspection detail.</Empty>
          </Panel>
        )}
      </div>
    </div>
  );
}

type Tab = 'summary' | 'checks' | 'ai' | 'explanation' | 'devices' | 'proof';
const TABS: Tab[] = ['summary', 'checks', 'ai', 'explanation', 'devices', 'proof'];

function Detail({
  release,
  publisher,
  entries,
  devices,
  health,
  policy,
  initialTab,
  onTab,
}: {
  release: Release;
  publisher: Publisher | undefined;
  entries: VerificationResult[];
  devices: Device[];
  health: Health | null;
  policy: Policy | null;
  initialTab?: Tab;
  onTab: (tab: Tab) => void;
}) {
  const toast = useToast();
  const fleetLevel =
    entries.filter((e) => e.deviceId === 'release-level').at(-1) ?? entries.at(-1) ?? null;
  const perDevice = new Map<string, VerificationResult>();
  for (const e of entries) if (e.deviceId !== 'release-level') perDevice.set(e.deviceId, e);
  const installed = devices.filter((d) => d.installed_release_id === release.releaseId);
  const stage1 = fleetLevel?.stage1 ?? null;
  const ran = new Map(stage1?.checks.map((c) => [c.name, c]) ?? []);
  const stand = standing(fleetLevel?.reputation ?? publisher?.reputation);
  const [tab, setTabState] = useState<Tab>(initialTab ?? 'summary');
  const setTab = (t: Tab) => {
    setTabState(t);
    onTab(t);
  };
  const [ask, setAsk] = useState(0);
  const [explainState, setExplainState] = useState<string | null>(null);
  const [proof, setProof] = useState<{ p: Proof; onChain: boolean | null } | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    setProof(null);
    setTabState(initialTab ?? 'summary');
  }, [release.releaseId, initialTab]);

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
      toast(`Could not fetch the proof: ${(err as Error).message}`, 'bad');
    } finally {
      setBusy(false);
    }
  };

  const marks = policy
    ? [
        { at: policy.tau_approve, label: 'approve' },
        { at: policy.tau_reject, label: 'reject' },
      ]
    : [];
  const tone = (v: number | null | undefined) =>
    v === null || v === undefined ? 'none' : v < 4500 ? 'ok' : v < 7000 ? 'warn' : 'bad';

  return (
    <section className="panel">
      <div className="detail-h">
        <div>
          <h2>
            {release.version} <span className="muted">for {release.deviceModel}</span>
          </h2>
          <div className="meta">
            {publisher?.did.replace('did:verigate:', '') ?? 'unknown publisher'} · standing{' '}
            <b className={stand.tone}>{stand.label}</b>
            {fleetLevel ? ` · inspected ${fmtDate(fleetLevel.checkedAt)}` : ''}
          </div>
          <p className="lede">
            {release.revoked
              ? 'Withdrawn by the publisher. Devices refuse it.'
              : fleetLevel
                ? reasonWords(fleetLevel)
                : 'Not inspected yet — the gateway picks up new releases within seconds.'}
          </p>
        </div>
        <div className="detail-side">
          <Stamp
            verdict={fleetLevel?.verdict ?? release.lastVerdict}
            revoked={release.revoked}
            big
          />
          {fleetLevel && stage1?.ok && !release.revoked && (
            <button
              className="btn-primary"
              title={
                explainState === 'ready'
                  ? 'Show the written explanation'
                  : 'Ask the local language model to explain this verdict in plain words'
              }
              disabled={explainState === 'writing'}
              onClick={() => {
                setTab('explanation');
                setAsk((n) => n + 1);
              }}
            >
              {explainState === 'writing'
                ? 'Writing…'
                : explainState === 'ready'
                  ? 'Show explanation'
                  : 'Explain with AI'}
            </button>
          )}
        </div>
      </div>
      <Tabs
        tabs={[
          { id: 'summary', label: 'Summary' },
          { id: 'checks', label: 'Checks' },
          { id: 'ai', label: 'AI' },
          { id: 'explanation', label: 'Explanation' },
          { id: 'devices', label: installed.length ? `Devices · ${installed.length}` : 'Devices' },
          { id: 'proof', label: 'Proof' },
        ]}
        value={tab}
        onChange={setTab}
      />
      <div className="panel-b">
        {tab === 'summary' &&
          (fleetLevel && stage1?.ok ? (
            <div className="meters">
              <Meter
                label="Known-vulnerability exposure"
                value={fleetLevel.rSbom}
                tone={tone(fleetLevel.rSbom)}
              />
              <Meter
                label="Unusual binary structure"
                value={fleetLevel.rImg}
                tone={tone(fleetLevel.rImg)}
              />
              <Meter
                label="Publisher standing, as risk"
                value={fleetLevel.reputation === null ? null : 10000 - fleetLevel.reputation}
                tone={tone(fleetLevel.reputation === null ? null : 10000 - fleetLevel.reputation)}
              />
              <Meter
                label="Overall risk"
                value={fleetLevel.R}
                tone={VERDICT_TONE[fleetLevel.verdict]}
                marks={marks}
                overall
              />
            </div>
          ) : (
            <dl className="kv">
              <dt>Outcome</dt>
              <dd>{fleetLevel ? VERDICT_WORD[fleetLevel.verdict] : 'Pending'}</dd>
              {stage1 && !stage1.ok && (
                <>
                  <dt>Stopped at</dt>
                  <dd>{failureWords(stage1.failed, stage1.reason)}</dd>
                </>
              )}
              <dt>Registered</dt>
              <dd>block {release.registeredAt}</dd>
            </dl>
          ))}
        {tab === 'checks' && (
          <ul className="checks">
            {CHECKS.map((c) => {
              const r = ran.get(c.name);
              const cls = !r ? 'skipped' : r.ok ? 'pass' : 'fail';
              return (
                <li key={c.name} className={cls}>
                  <span className="mark" aria-hidden="true">
                    {!r ? '·' : r.ok ? '✓' : '✕'}
                  </span>
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
        )}
        {tab === 'ai' &&
          (fleetLevel && stage1?.ok ? (
            <AiSaw stage2={fleetLevel.stage2} />
          ) : (
            <p className="muted">The models did not run: the release was stopped by the checks.</p>
          ))}
        {tab === 'explanation' && (
          <ExplanationBox
            releaseId={release.releaseId}
            hasStage2={Boolean(fleetLevel && stage1?.ok)}
            ask={ask}
            onStatus={setExplainState}
          />
        )}
        {tab === 'devices' && (
          <>
            <div className="counts">
              <div>
                <div className="n">{installed.length}</div>
                <div className="l">installed</div>
              </div>
              {(['APPROVE', 'DEFER', 'REJECT'] as const).map((k) => (
                <div key={k}>
                  <div className="n">
                    {[...perDevice.values()].filter((v) => v.verdict === k).length}
                  </div>
                  <div className="l">{VERDICT_WORD[k].toLowerCase()}</div>
                </div>
              ))}
            </div>
            {perDevice.size > 0 && (
              <table className="data" style={{ marginTop: 14 }}>
                <thead>
                  <tr>
                    <th>Device</th>
                    <th>Verdict</th>
                    <th>When</th>
                  </tr>
                </thead>
                <tbody>
                  {[...perDevice.values()].map((v) => (
                    <tr key={v.deviceId}>
                      <td>{v.deviceId}</td>
                      <td>
                        <Stamp verdict={v.verdict} />
                      </td>
                      <td className="muted">
                        <Time iso={v.checkedAt} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </>
        )}
        {tab === 'proof' && (
          <>
            {fleetLevel?.verdictId ? (
              <>
                <p>
                  <button onClick={() => void checkOnChain()} disabled={busy}>
                    {busy ? 'Checking…' : 'Verify on the blockchain'}
                  </button>
                </p>
                {proof && (
                  <p
                    className={`notice ${proof.p.status === 'pending' ? 'warn' : proof.onChain ? 'ok' : 'bad'}`}
                  >
                    {proof.p.status === 'pending'
                      ? 'Not anchored yet — it goes on-chain with the next batch.'
                      : proof.onChain
                        ? `Verified on-chain: batch ${proof.p.batchId}, block ${proof.p.blockNumber}.`
                        : 'The chain did not confirm this proof.'}
                  </p>
                )}
              </>
            ) : (
              <p className="muted">No anchored decision yet.</p>
            )}
            <details className="tech" style={{ marginTop: 12 }}>
              <summary>Identifiers</summary>
              <dl>
                <dt>Release</dt>
                <dd>
                  <Id value={release.releaseId} chars={20} />
                </dd>
                <dt>Decision</dt>
                <dd>
                  <Id value={fleetLevel?.verdictId} chars={20} />
                </dd>
                <dt>Manifest CID</dt>
                <dd>
                  <Id value={release.manifestCid} chars={20} />
                </dd>
                <dt>Models</dt>
                <dd>
                  {(fleetLevel?.modelHashes ?? []).map((h) => (
                    <div key={h}>
                      <Id value={h} chars={20} />
                    </div>
                  ))}
                  {(fleetLevel?.modelHashes ?? []).length === 0 && '—'}
                </dd>
                {stage1 && !stage1.ok && (
                  <>
                    <dt>Failure detail</dt>
                    <dd>{stage1.reason}</dd>
                  </>
                )}
              </dl>
            </details>
          </>
        )}
      </div>
    </section>
  );
}
