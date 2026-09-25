/** Publisher identity: who the portal publishes as, standing, signing key. */
import { api } from '../../api/client';
import { Id, Kpi, Panel } from '../../components/Bits';
import { usePoll } from '../../components/usePoll';
import { bp, standing } from '../../lib/words';

export function PubIdentity() {
  const me = usePoll(api.me, 10000);
  const m = me.data;
  const stand = standing(m?.reputation);
  return (
    <>
      <div className="kpis">
        <Kpi
          label="Standing"
          value={<span className={stand.tone}>{stand.label}</span>}
          sub={m ? `${bp(m.reputation)} of 1.00` : ''}
        />
        <Kpi
          label="Registration"
          value={m ? (m.registered ? 'Registered' : 'Not registered') : '—'}
        />
        <Kpi label="Signing key version" value={m?.keyVersion ?? '—'} />
      </div>
      <Panel title="Identity">
        {me.error && <p className="notice bad">{me.error}</p>}
        {m ? (
          <dl className="kv">
            <dt>Publisher</dt>
            <dd>{m.did.replace('did:verigate:', '')}</dd>
            <dt>DID</dt>
            <dd>
              <code>{m.did}</code>
            </dd>
            <dt>Publisher id</dt>
            <dd>
              <Id value={m.publisherId} chars={20} />
            </dd>
            <dt>Signing key</dt>
            <dd>
              <Id value={m.publicKey} chars={20} />
            </dd>
          </dl>
        ) : (
          <p className="muted">Loading…</p>
        )}
      </Panel>
    </>
  );
}
