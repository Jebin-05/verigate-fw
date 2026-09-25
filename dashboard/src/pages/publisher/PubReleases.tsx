/** Publisher: own releases as a table, a "New release" dialog, withdraw. */
import { useMemo, useState, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../api/client';
import type { Release, VerificationResult } from '../../api/types';
import { Confirm, Empty, Kpi, Loading, Modal, Panel, Stamp, Time } from '../../components/Bits';
import { usePoll } from '../../components/usePoll';
import { isVerdict, reasonWords } from '../../lib/words';
import { useToast } from '../../state/store';

function nextVersion(releases: Release[], model: string): string {
  const own = releases
    .filter((r) => r.deviceModel === model)
    .map((r) => r.version.split('.').map(Number));
  if (own.length === 0) return '1.0.0';
  const [a, b, c] = own.sort((x, y) => x[0] - y[0] || x[1] - y[1] || x[2] - y[2]).at(-1)!;
  return `${a}.${b}.${c + 1}`;
}

/** True when `candidate` is strictly higher than every version already published for `model`. */
function isNewer(releases: Release[], model: string, candidate: string): boolean {
  const c = candidate.split('.').map(Number);
  if (c.length !== 3 || c.some((n) => Number.isNaN(n))) return false;
  return releases
    .filter((r) => r.deviceModel === model)
    .map((r) => r.version.split('.').map(Number))
    .every(([a, b, d]) => c[0] > a || (c[0] === a && (c[1] > b || (c[1] === b && c[2] > d))));
}

function yearFromNow(): string {
  const d = new Date();
  d.setFullYear(d.getFullYear() + 1);
  return d.toISOString().slice(0, 10);
}

export function PubReleases({ openForm = false }: { openForm?: boolean }) {
  const navigate = useNavigate();
  const me = usePoll(api.me, 10000);
  const releases = usePoll(api.releases, 3000);
  const devices = usePoll(api.devices, 5000);
  const verdicts = usePoll(api.verdicts, 4000);
  const mine = useMemo(
    () =>
      (releases.data ?? [])
        .filter((r) => me.data && r.publisherId === me.data.publisherId)
        .slice()
        .reverse(),
    [releases.data, me.data],
  );
  const fleet = useMemo(() => {
    const m = new Map<string, VerificationResult>();
    for (const e of (verdicts.data ?? []).filter(isVerdict))
      if (e.deviceId === 'release-level') m.set(e.releaseId, e);
    return m;
  }, [verdicts.data]);
  const installedCount = (id: string) =>
    (devices.data ?? []).filter((d) => d.installed_release_id === id).length;
  const models = useMemo(() => Array.from(new Set(mine.map((r) => r.deviceModel))).sort(), [mine]);

  const [showForm, setShowForm] = useState(openForm);
  const [pending, setPending] = useState<Release | null>(null);
  const [withdrawing, setWithdrawing] = useState(false);
  const toast = useToast();

  const withdraw = async (r: Release) => {
    setWithdrawing(true);
    try {
      await api.withdraw(r.releaseId);
      toast(`${r.version} for ${r.deviceModel} withdrawn. Devices refuse it from now on.`, 'ok');
      setPending(null);
      void releases.refresh();
    } catch (err) {
      toast(`Could not withdraw ${r.version}: ${(err as Error).message}`, 'bad');
    } finally {
      setWithdrawing(false);
    }
  };

  const counts = { APPROVE: 0, DEFER: 0, REJECT: 0 };
  for (const r of mine) if (r.lastVerdict && !r.revoked) counts[r.lastVerdict] += 1;

  return (
    <>
      <div className="kpis">
        <Kpi label="Your releases" value={mine.length} />
        <Kpi label="Approved" value={<span className="ok">{counts.APPROVE}</span>} />
        <Kpi label="Needs review" value={<span className="warn">{counts.DEFER}</span>} />
        <Kpi label="Rejected" value={<span className="bad">{counts.REJECT}</span>} />
        <Kpi
          label="Devices on your firmware"
          value={
            (devices.data ?? []).filter((d) =>
              mine.some((r) => r.releaseId === d.installed_release_id),
            ).length
          }
        />
      </div>
      <Panel
        title="Releases"
        flush
        actions={
          <button className="btn-primary" onClick={() => setShowForm(true)} disabled={!me.data}>
            New release
          </button>
        }
      >
        {releases.error && <p className="notice bad">{releases.error}</p>}
        {releases.loading || me.loading ? (
          <Loading what="releases" />
        ) : mine.length === 0 ? (
          <Empty>No releases yet. Use “New release” to publish your first one.</Empty>
        ) : (
          <table className="data">
            <thead>
              <tr>
                <th>Version</th>
                <th>Model</th>
                <th>Status</th>
                <th>Inspected</th>
                <th className="num">Installed on</th>
                <th>Notes</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {mine.map((r) => {
                const f = fleet.get(r.releaseId);
                return (
                  <tr key={r.releaseId}>
                    <td>
                      <b>{r.version}</b>
                    </td>
                    <td>{r.deviceModel}</td>
                    <td>
                      <Stamp verdict={r.lastVerdict} revoked={r.revoked} />
                    </td>
                    <td className="muted">
                      <Time iso={r.lastVerdictAt} />
                    </td>
                    <td className="num">{installedCount(r.releaseId)}</td>
                    <td className="wrap muted" style={{ maxWidth: 380 }}>
                      {r.revoked ? 'Withdrawn' : f && f.verdict !== 'APPROVE' ? reasonWords(f) : ''}
                    </td>
                    <td>
                      {!r.revoked && (
                        <button className="btn-sm btn-danger" onClick={() => setPending(r)}>
                          Withdraw
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </Panel>
      {pending && (
        <Confirm
          title={`Withdraw ${pending.version}?`}
          confirmLabel="Withdraw release"
          danger
          busy={withdrawing}
          onCancel={() => setPending(null)}
          onConfirm={() => void withdraw(pending)}
        >
          <p>
            Devices running <b>{pending.deviceModel}</b> will refuse {pending.version} from now on,
            and the approval console will show it as withdrawn. This cannot be undone; publish a new
            version instead.
          </p>
        </Confirm>
      )}
      {showForm && (
        <NewRelease
          models={models}
          suggested={(m) => nextVersion(mine, m)}
          newer={(m, v) => isNewer(mine, m, v)}
          onClose={() => {
            setShowForm(false);
            if (openForm) navigate('/publisher');
          }}
          onDone={(text) => {
            toast(text, 'ok');
            void releases.refresh();
          }}
        />
      )}
    </>
  );
}

function NewRelease({
  models,
  suggested,
  newer,
  onClose,
  onDone,
}: {
  models: string[];
  suggested: (model: string) => string;
  newer: (model: string, version: string) => boolean;
  onClose: () => void;
  onDone: (text: string) => void;
}) {
  const [model, setModel] = useState(models[0] ?? 'demo-device');
  const [version, setVersion] = useState('');
  const [expiry, setExpiry] = useState(yearFromNow());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const hint = suggested(model || 'demo-device');
  const versionProblem =
    version && !/^\d+\.\d+\.\d+$/.test(version)
      ? 'Use MAJOR.MINOR.PATCH, for example 1.2.0.'
      : version && !newer(model || 'demo-device', version)
        ? `Must be higher than every version already published for ${model || 'demo-device'}.`
        : null;

  const submit = async (ev: FormEvent<HTMLFormElement>) => {
    ev.preventDefault();
    if (versionProblem) return;
    const form = new FormData(ev.currentTarget);
    form.set('device_model', model || 'demo-device');
    form.set('version', version || hint);
    form.set('expiry', `${expiry}T00:00:00Z`);
    setBusy(true);
    setError(null);
    try {
      const result = await api.publish(form);
      onDone(
        `Published ${result.version} for ${result.deviceModel}. It is being inspected; the status updates within seconds.`,
      );
      onClose();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title="New release" onClose={onClose}>
      <form id="new-release" onSubmit={(ev) => void submit(ev)}>
        <div className="grid-2">
          <div className="field">
            <label htmlFor="model">Device model</label>
            <input
              id="model"
              list="models"
              value={model}
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
              placeholder={hint}
              onChange={(e) => setVersion(e.target.value)}
              aria-invalid={Boolean(versionProblem)}
            />
            <div className={versionProblem ? 'hint bad' : 'hint'}>
              {versionProblem ?? `Leave empty to use ${hint}.`}
            </div>
          </div>
        </div>
        <div className="grid-2">
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
        <div className="grid-2">
          <div className="field">
            <label htmlFor="expiry">Valid until</label>
            <input
              id="expiry"
              type="date"
              value={expiry}
              onChange={(e) => setExpiry(e.target.value)}
              required
            />
          </div>
        </div>
        {error && <p className="notice bad">Not published: {error}</p>}
        <div className="modal-actions" style={{ padding: '4px 0 0', borderTop: 0 }}>
          <button type="button" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" className="btn-primary" disabled={busy || Boolean(versionProblem)}>
            {busy ? 'Publishing…' : 'Publish release'}
          </button>
        </div>
      </form>
    </Modal>
  );
}
