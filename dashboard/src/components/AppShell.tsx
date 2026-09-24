/** Application shell: persistent sidebar (workspace, navigation, status) + top bar + outlet. */
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { api } from '../api/client';
import { usePoll } from './usePoll';

export type Workspace = 'approver' | 'publisher';

const NAV: Record<Workspace, { to: string; label: string; ico: string; end?: boolean }[]> = {
  approver: [
    { to: '/app', label: 'Overview', ico: '◫', end: true },
    { to: '/app/releases', label: 'Releases', ico: '▤' },
    { to: '/app/devices', label: 'Devices', ico: '▣' },
    { to: '/app/activity', label: 'Activity', ico: '≡' },
    { to: '/app/governance', label: 'Governance', ico: '⚖' },
    { to: '/app/scenarios', label: 'Scenarios', ico: '▶' },
  ],
  publisher: [
    { to: '/publisher', label: 'Releases', ico: '▤', end: true },
    { to: '/publisher/new', label: 'New release', ico: '+' },
    { to: '/publisher/identity', label: 'Identity', ico: '◉' },
  ],
};

const TITLES: Record<string, string> = {
  '/app': 'Overview',
  '/app/releases': 'Releases',
  '/app/devices': 'Devices',
  '/app/activity': 'Activity',
  '/app/governance': 'Governance',
  '/app/scenarios': 'Scenarios',
  '/publisher': 'Releases',
  '/publisher/new': 'New release',
  '/publisher/identity': 'Identity',
};

export function AppShell({ workspace }: { workspace: Workspace }) {
  const { data: health, error } = usePoll(api.health, 5000);
  const loc = useLocation();
  const up = !error && health?.status === 'ok';
  const title = TITLES[loc.pathname] ?? '';
  const other = workspace === 'approver' ? 'publisher' : 'approver';
  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="mark">V</span> VeriGate
        </div>
        <div className="workspace">
          <b>{workspace === 'approver' ? 'Approval console' : 'Publisher portal'}</b>
          <Link to={other === 'approver' ? '/app' : '/publisher'}>
            Switch to {other === 'approver' ? 'approval console' : 'publisher portal'}
          </Link>
        </div>
        <nav>
          {NAV[workspace].map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end}>
              <span className="ico">{n.ico}</span>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="sb-foot">
          <div>
            <span className={`dot ${up ? 'on' : 'off'}`} />
            <b>{up ? 'Gateway connected' : 'Gateway unreachable'}</b>
          </div>
          <div>
            Chain {health?.chain ? `block ${health.block ?? '—'}` : 'unreachable'} · id{' '}
            {health?.chainId ?? '—'}
          </div>
          <div>
            {health?.knownReleases ?? '—'} releases · {health?.devices ?? '—'} devices ·{' '}
            {health?.batches ?? '—'} batches on-chain
          </div>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <span className="crumbs">
            {workspace === 'approver' ? 'Approval console' : 'Publisher portal'} /
          </span>
          <h1>{title}</h1>
          <span className="spacer" />
          <span className="small muted">{up ? 'Live' : 'Offline'}</span>
        </header>
        <div className="content">
          <Outlet context={health} />
        </div>
      </div>
    </div>
  );
}
