/** Application shell: persistent sidebar (workspace, navigation) + top bar + outlet. */
import { useEffect } from 'react';
import { Link, NavLink, Outlet, useLocation } from 'react-router-dom';
import { api } from '../api/client';
import { Toaster } from './Bits';
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
  const releases = usePoll(api.releases, 6000);
  const loc = useLocation();
  const up = !error && health?.status === 'ok';
  const title = TITLES[loc.pathname] ?? '';
  const wsName = workspace === 'approver' ? 'Approval console' : 'Publisher portal';
  const other = workspace === 'approver' ? 'publisher' : 'approver';
  const attention =
    workspace === 'approver'
      ? (releases.data ?? []).filter((r) => !r.revoked && r.lastVerdict === 'DEFER').length
      : 0;

  useEffect(() => {
    document.title = title ? `${title} · VeriGate` : 'VeriGate';
  }, [title]);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="mark">V</span> VeriGate
        </div>
        <div className="workspace">
          <b>{wsName}</b>
          <Link to={other === 'approver' ? '/app' : '/publisher'}>
            Switch to {other === 'approver' ? 'approval console' : 'publisher portal'}
          </Link>
        </div>
        <nav aria-label="Main">
          {NAV[workspace].map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end}>
              <span className="ico">{n.ico}</span>
              {n.label}
              {n.to === '/app/releases' && attention > 0 && (
                <span className="badge" title={`${attention} release(s) need review`}>
                  {attention}
                </span>
              )}
            </NavLink>
          ))}
        </nav>
        <div className="sb-foot">
          <span className="ver">v{__APP_VERSION__}</span>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <span className="crumbs">{wsName} /</span>
          <h1>{title}</h1>
          <span className="spacer" />
          <span className={`small ${up ? 'muted' : 'bad'}`}>{up ? 'Live' : 'Offline'}</span>
        </header>
        {!up && (
          <div className="offline" role="alert">
            The gateway is not responding. Data on this page may be stale; it reconnects
            automatically.
          </div>
        )}
        <div className="content">
          <Outlet context={health} />
        </div>
      </div>
      <Toaster />
    </div>
  );
}
