import { useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import { api } from '../api/client';
import type { Health, Proof, Rationale, VerificationResult } from '../api/types';
import { verifyLeafOnChain } from '../chain/useChain';
import { ErrorLine, Hex, Panel, Table, VerdictBadge } from '../components/ui';
import { usePoll } from '../components/usePoll';

export function Verdicts() {
  const health = useOutletContext<Health | null>();
  const { data, error } = usePoll(() => api.verdicts(200), 3000);
  const batches = usePoll(api.batches, 5000);
  const [proof, setProof] = useState<Proof | null>(null);
  const [onChain, setOnChain] = useState<string>('');
  const [rationale, setRationale] = useState<Rationale | null>(null);

  const showRationale = async (cid: string) => {
    try {
      setRationale(await api.rationale(cid));
    } catch (err) {
      alert(String(err));
    }
  };

  const showProof = async (verdictId: string) => {
    setOnChain('');
    try {
      const p = await api.proof(verdictId);
      setProof(p);
      if (p.status === 'committed' && health?.contracts && p.batchId !== undefined && p.proof) {
        const ok = await verifyLeafOnChain(
          health.contracts.VerdictRegistry,
          p.batchId,
          p.verdictId,
          p.proof,
        );
        setOnChain(
          ok ? 'VerdictRegistry.verifyLeaf → true (checked via direct RPC)' : 'verifyLeaf → FALSE',
        );
      }
    } catch (err) {
      alert(String(err));
    }
  };

  const verdicts = (data ?? []).filter((e): e is VerificationResult => 'verdict' in e).reverse();
  return (
    <>
      <Panel
        title="Verdicts (newest first)"
        actions={
          <button onClick={() => void api.flush().then(() => batches.refresh())}>
            commit pending batch
          </button>
        }
      >
        <ErrorLine error={error} />
        <Table
          headers={[
            'time',
            'release',
            'device',
            'verdict',
            'failed check / reason',
            'R (bp)',
            'verdict id',
            '',
          ]}
        >
          {verdicts.map((v, i) => (
            <tr key={`${v.verdictId ?? i}-${v.checkedAt}`}>
              <td>{v.checkedAt.slice(11, 19)}</td>
              <td>
                <Hex value={v.releaseId} />
              </td>
              <td>{v.deviceId}</td>
              <td>
                <VerdictBadge verdict={v.verdict} />
              </td>
              <td>
                {v.stage1?.failed ? <b>{v.stage1.failed}: </b> : null}
                {v.reason}
              </td>
              <td>{v.R ?? '—'}</td>
              <td>
                <Hex value={v.verdictId} />
              </td>
              <td>
                {v.verdictId && <button onClick={() => void showProof(v.verdictId!)}>proof</button>}{' '}
                {v.rationaleCid && (
                  <button onClick={() => void showRationale(v.rationaleCid!)}>why</button>
                )}
              </td>
            </tr>
          ))}
        </Table>
      </Panel>
      {proof && (
        <Panel title={`Merkle proof for ${proof.verdictId.slice(0, 12)}…`}>
          {proof.status === 'pending' ? (
            <p>pending — not yet committed (batch flushes on size or time, ADR-0005)</p>
          ) : (
            <>
              <p>
                batch <b>{proof.batchId}</b> · root <Hex value={proof.root} /> · tx{' '}
                <Hex value={proof.txHash} /> · block {proof.blockNumber} · index {proof.index} ·
                siblings {proof.proof?.length}
              </p>
              <p className={onChain.includes('true') ? 'ok' : 'bad'}>{onChain}</p>
              <pre>{JSON.stringify(proof.record, null, 2)}</pre>
            </>
          )}
        </Panel>
      )}
      {rationale && (
        <Panel title="LLM rationale (explanatory only — never part of R, ADR-0002)">
          <p>{rationale.summary}</p>
          {rationale.top_risks.length > 0 && (
            <ul>
              {rationale.top_risks.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          )}
          <p>
            suggested action: <b>{rationale.recommended_action}</b> · cid{' '}
            <Hex value={rationale.cid} />
          </p>
        </Panel>
      )}
      <Panel title="Committed batches">
        <Table headers={['batch', 'count', 'root', 'tx', 'block', 'models']}>
          {(batches.data ?? []).map((b) => (
            <tr key={b.batchId}>
              <td>{b.batchId}</td>
              <td>{b.count}</td>
              <td>
                <Hex value={b.root} />
              </td>
              <td>
                <Hex value={b.txHash} />
              </td>
              <td>{b.blockNumber}</td>
              <td>{b.modelHashes.length}</td>
            </tr>
          ))}
        </Table>
      </Panel>
    </>
  );
}
