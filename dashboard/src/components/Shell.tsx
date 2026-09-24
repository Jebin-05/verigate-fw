/** Top bar shared by the portals: product name, which portal you are in, a way back, connection. */
import { Link, Outlet } from 'react-router-dom';
import { api } from '../api/client';
import { usePoll } from './usePoll';

export function Shell({ role }: { role: string }) {
  const { data: health, error } = usePoll(api.health, 5000);
  const up = !error && health?.status === 'ok';
  return (
    <>
      <header className="topbar">
        <Link className="brand" to="/">
          VeriGate
        </Link>
        <span className="role">{role}</span>
        <span className="spacer" />
        <span className="conn" title={error ?? undefined}>
          <span className={`dot ${up ? 'on' : 'off'}`} />
          {up ? 'Connected' : 'Gateway unreachable'}
        </span>
        <Link to="/" className="small">
          Switch portal
        </Link>
      </header>
      <Outlet context={health} />
    </>
  );
}
