/** Publisher portal: who you are, publish a release, follow your own releases. Nothing else. */
import { useMemo, useState, type FormEvent } from 'react';
import { api } from '../api/client';
import type { Device, Release, VerificationResult } from '../api/types';
import { Empty, Stamp } from '../components/Bits';
import { usePoll } from '../components/usePoll';
import { bp, fmtDate, reasonWords, standing } from '../lib/words';

function nextVersion(releases: Release[], model: string): string {
  const own = releases
    .filter((r) => r.deviceModel === model)
    .map((r) => r.version.split('.').map(Number));
  if (own.length === 0) return '1.0.0';
  const [a, b, c] = own.sort((x, y) => x[0] - y[0] || x[1] - y[1] || x[2] - y[2]).at(-1)!;
  return `${a}.${b}.${c + 1}`;
}

function yearFromNow(): string {
  const d = new Date();
  d.setFullYear(d.getFullYear() + 1);
  return d.toISOString().slice(0, 10);
}

export function Publisher() {
  const me = usePoll(api.me, 10000);
  const releases = usePoll(api.releases, 3000);
  const devices = usePoll(api.devices, 5000);
  const verdicts = usePoll(api.verdicts, 3000);

  const mine = useMemo(
    () =>
      (releases.data ?? [])
        .filter((r) => me.data && r.publisherId === me.data.publisherId)
        .slice()
        .reverse(),
    [releases.data, me.data],
  );
  const models = useMemo(() => Array.from(new Set(mine.map((r) => r.deviceModel))).sort(), [mine]);

  const [model, setModel] = useState('');
  const [version, setVersion] = useState('');
  const [expiry, setExpiry] = useState(yearFromNow());
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ text: string; tone: 'ok' | 'bad' } | null>(null);

  const effectiveModel = model || models[0] || 'demo-device';
  const suggested = nextVersion(mine, effectiveModel);

  const submit = async (ev: FormEvent<HTMLFormElement>) => {
    ev.preventDefault();
    const formEl = ev.currentTarget; // React clears currentTarget once the handler yields
    const form = new FormData(formEl);
    form.set('device_model', effectiveModel);
    form.set('version', version || suggested);
    form.set('expiry', `${expiry}T00:00:00Z`);
    setBusy(true);
    setMessage(null);
    try {
      const result = await api.publish(form);
      setMessage({
        text: `Published ${result.version} for ${result.deviceModel}. It is registered on the blockchain and being inspected now — the result appears below within a few seconds.`,
        tone: 'ok',
      });
      setVersion('');
      formEl.reset();
      void releases.refresh();
    } catch (err) {
      setMessage({ text: `Not published: ${(err as Error).message}`, tone: 'bad' });
    } finally {
      setBusy(false);
    }
  };

  const withdraw = async (r: Release) => {
    if (
      !window.confirm(
        `Withdraw ${r.version} for ${r.deviceModel}? Devices will refuse it from now on. This cannot be undone.`,
      )
    )
      return;
    try {
      await api.withdraw(r.releaseId);
      void releases.refresh();
    } catch (err) {
      window.alert(`Could not withdraw: ${(err as Error).message}`);
    }
  };

  const stand = standing(me.data?.reputation);

  return (
    <main className="page narrow">
      <div className="page-head">
        <h1>Publisher portal</h1>
        {me.data ? (
          <p>
            Publishing as <b>{me.data.did.replace('did:verigate:', '')}</b>
            {me.data.registered ? (
              <>
                {' '}
                · standing <b className={stand.tone}>{stand.label}</b> ({bp(me.data.reputation)}) ·
                signing key registered
              </>
            ) : (
              <> · not registered yet — the first release registers you</>
            )}
          </p>
        ) : (
          <p>{me.error ? 'The gateway is not reachable right now.' : 'Loading your identity…'}</p>
        )}
      </div>

      <section className="block">
        <h2>Publish a release</h2>
        <form className="sheet" onSubmit={(ev) => void submit(ev)}>
          <div className="field-row">
            <div className="field">
              <label htmlFor="model">Device model</label>
              <input
                id="model"
                list="models"
                value={model}
                placeholder={effectiveModel}
                onChange={(e) => setModel(e.target.value)}
              />
              <datalist id="models">
                {models.map((m) => (
                  <option key={m} value={m} />
                ))}
              </datalist>
            </div>
            <div className="field">
              <label htmlFor="version">Version</label>
              <input
                id="version"
                value={version}
                placeholder={suggested}
                onChange={(e) => setVersion(e.target.value)}
                pattern="\d+\.\d+\.\d+"
                title="MAJOR.MINOR.PATCH, e.g. 2.1.0"
              />
              <div className="hint">
                Must be higher than your last release for this model. Suggested: {suggested}
              </div>
            </div>
          </div>
          <div className="field-row">
            <div className="field">
              <label htmlFor="firmware">Firmware file</label>
              <input id="firmware" name="firmware" type="file" required />
              <div className="hint">The exact image devices will install.</div>
            </div>
            <div className="field">
              <label htmlFor="sbom">Ingredient list (SBOM)</label>
              <input id="sbom" name="sbom" type="file" accept=".json,application/json" required />
              <div className="hint">CycloneDX JSON listing every package in the build.</div>
            </div>
          </div>
          <div className="field-row">
            <div className="field">
              <label htmlFor="expiry">Valid until</label>
              <input
                id="expiry"
                type="date"
                value={expiry}
                onChange={(e) => setExpiry(e.target.value)}
                required
              />
              <div className="hint">After this date devices treat the release as stale.</div>
            </div>
          </div>
          <button className="primary" type="submit" disabled={busy || !me.data}>
            {busy ? 'Publishing…' : 'Publish release'}
          </button>
          {message && <p className={`notice ${message.tone}`}>{message.text}</p>}
        </form>
      </section>

      <section className="block">
        <h2>Your releases</h2>
        {releases.error && <p className="notice bad">Could not load releases: {releases.error}</p>}
        {mine.length === 0 ? (
          <Empty>No releases yet. Your first one will appear here after you publish it.</Empty>
        ) : (
          <ul className="rows">
            {mine.map((r) => (
              <ReleaseRow
                key={r.releaseId}
                release={r}
                devices={devices.data ?? []}
                latest={latestVerdict(verdicts.data ?? [], r.releaseId)}
                onWithdraw={withdraw}
              />
            ))}
          </ul>
        )}
      </section>
    </main>
  );
}

function latestVerdict(entries: unknown[], releaseId: string): VerificationResult | null {
  const own = entries.filter(
    (e): e is VerificationResult =>
      typeof e === 'object' &&
      e !== null &&
      'verdict' in e &&
      (e as VerificationResult).releaseId === releaseId &&
      (e as VerificationResult).deviceId === 'release-level',
  );
  return own.at(-1) ?? null;
}

function ReleaseRow({
  release: r,
  devices,
  latest,
  onWithdraw,
}: {
  release: Release;
  devices: Device[];
  latest: VerificationResult | null;
  onWithdraw: (r: Release) => void;
}) {
  const installed = devices.filter((d) => d.installed_release_id === r.releaseId).length;
  const inspected = r.lastVerdict !== null;
  const approved = r.lastVerdict === 'APPROVE';
  return (
    <li>
      <div>
        <div className="title">
          {r.version} <span className="muted">for {r.deviceModel}</span>
        </div>
        <div className="journey">
          <span className="step done">
            <span className="tick">✓</span> Signed and registered
          </span>
          <span className="arrow">›</span>
          <span className={`step ${inspected ? 'done' : 'todo'}`}>
            <span
              className={`tick ${inspected ? (approved ? '' : r.lastVerdict === 'DEFER' ? 'warn' : 'bad') : 'pending'}`}
            >
              {inspected ? (approved ? '✓' : '!') : '…'}
            </span>
            {inspected ? `Inspected ${fmtDate(r.lastVerdictAt)}` : 'Inspection pending'}
          </span>
          <span className="arrow">›</span>
          <span className={`step ${installed > 0 ? 'done' : 'todo'}`}>
            <span className={`tick ${installed > 0 ? '' : 'pending'}`}>
              {installed > 0 ? '✓' : '…'}
            </span>
            {installed > 0
              ? `Installed on ${installed} device${installed === 1 ? '' : 's'}`
              : 'Not installed yet'}
          </span>
        </div>
        {latest && latest.verdict !== 'APPROVE' && !r.revoked && (
          <div className="sub" style={{ marginTop: 6 }}>
            {reasonWords(latest)}
          </div>
        )}
      </div>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
        <Stamp verdict={r.lastVerdict} revoked={r.revoked} />
        {!r.revoked && (
          <button className="danger" onClick={() => onWithdraw(r)}>
            Withdraw
          </button>
        )}
      </div>
    </li>
  );
}
