import { useState } from 'react';
import { api } from '../api/client';
import type { VerificationResult } from '../api/types';
import { ErrorLine, Hex, Panel, Table, VerdictBadge } from '../components/ui';
import { usePoll } from '../components/usePoll';

export function Releases() {
  const { data, error, refresh } = usePoll(() => api.releases(true), 5000);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const verify = async (id: string) => {
    setBusy(id);
    try {
      setResult(await api.verify(id));
      await refresh();
    } catch (err) {
      setResult(null);
      alert(String(err));
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      <Panel title="Releases (FirmwareRegistry)">
        <ErrorLine error={error} />
        <Table
          headers={[
            'release',
            'model',
            'version',
            'publisher',
            'firmware CID',
            'block',
            'revoked',
            'last verdict',
            '',
          ]}
        >
          {(data ?? []).map((r) => (
            <tr key={r.releaseId}>
              <td>
                <Hex value={r.releaseId} />
              </td>
              <td>{r.deviceModel}</td>
              <td>{r.version}</td>
              <td>
                <Hex value={r.publisherId} chars={6} />
              </td>
              <td>
                <Hex value={r.firmwareCid} chars={8} />
              </td>
              <td>{r.registeredAt}</td>
              <td>{r.revoked ? 'yes' : 'no'}</td>
              <td>
                <VerdictBadge verdict={r.lastVerdict} />
              </td>
              <td>
                <button disabled={busy !== null} onClick={() => void verify(r.releaseId)}>
                  {busy === r.releaseId ? 'verifying…' : 'verify'}
                </button>
              </td>
            </tr>
          ))}
        </Table>
      </Panel>
      {result && (
        <Panel title={`Verification of ${result.releaseId.slice(0, 12)}…`}>
          <p>
            <VerdictBadge verdict={result.verdict} /> {result.reason ?? ''} · R=<b>{result.R}</b> bp
            · policy v{result.policyVersion ?? '—'} · reputation {result.reputation ?? '—'} bp ·
            verdict id <Hex value={result.verdictId} />
          </p>
          <Table headers={['#', 'check', 'ok', 'reason']}>
            {(result.stage1?.checks ?? []).map((c, i) => (
              <tr key={c.name} className={c.ok ? '' : 'row-fail'}>
                <td>{i + 1}</td>
                <td>{c.name}</td>
                <td>{c.ok ? '✔' : '✘'}</td>
                <td>{c.reason ?? ''}</td>
              </tr>
            ))}
          </Table>
          {result.errors.length > 0 && <p className="error">{result.errors.join('; ')}</p>}
        </Panel>
      )}
    </>
  );
}
