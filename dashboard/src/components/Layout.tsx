/** App shell: navigation, gateway/chain status bar, page outlet and the live log panel. */
import { NavLink, Outlet } from 'react-router-dom';
import { api, GATEWAY_URL } from '../api/client';
import { RPC_URL, useChain } from '../chain/useChain';
import { LiveLog } from './LiveLog';
import { usePoll } from './usePoll';

const PAGES = ['releases', 'verdicts', 'fleet', 'publishers', 'models', 'policy', 'attacks'];

export function Layout() {
  const { data: health, error } = usePoll(api.health, 5000);
  const chain = useChain(health?.contracts);
  return (
    <div className="app">
      <nav className="nav">
        <h1>VeriGate-FW</h1>
        {PAGES.map((p) => (
          <NavLink key={p} to={`/${p}`} className={({ isActive }) => (isActive ? 'active' : '')}>
            {p}
          </NavLink>
        ))}
        <div className="status">
          <div>
            gateway <b className={error ? 'bad' : 'ok'}>{error ? 'down' : 'ok'}</b>{' '}
            <span className="muted">{GATEWAY_URL}</span>
          </div>
          <div>
            chain <b className={health?.chain ? 'ok' : 'bad'}>{health?.chain ? 'ok' : 'down'}</b>{' '}
            <span className="muted">
              block {health?.block ?? '—'} · id {health?.chainId ?? '—'}
            </span>
          </div>
          <div>
            direct RPC <b className={chain.error ? 'bad' : 'ok'}>{chain.error ? 'down' : 'ok'}</b>{' '}
            <span className="muted">
              {RPC_URL} · batches {chain.batchCount ?? '—'} · policy v{chain.policyVersion ?? '—'}
            </span>
          </div>
          <div className="muted">
            releases {health?.knownReleases ?? '—'} · devices {health?.devices ?? '—'} · pending
            verdicts {health?.pendingVerdicts ?? '—'} · ipfs {health?.ipfsBackend ?? '—'}
          </div>
        </div>
      </nav>
      <main className="content">
        <Outlet context={health} />
      </main>
      <LiveLog />
    </div>
  );
}
