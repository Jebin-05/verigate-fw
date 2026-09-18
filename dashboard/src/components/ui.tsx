/** Small shared building blocks: hex ids, verdict badges, status chips, data tables. */
import type { ReactNode } from 'react';

export function Hex({ value, chars = 10 }: { value: string | null | undefined; chars?: number }) {
  if (!value) return <span className="muted">—</span>;
  const short =
    value.length > chars + 2 ? `${value.slice(0, chars + 2)}…${value.slice(-4)}` : value;
  return (
    <code className="hex" title={value}>
      {short}
    </code>
  );
}

export function VerdictBadge({ verdict }: { verdict: string | null | undefined }) {
  if (!verdict) return <span className="badge badge-none">none</span>;
  return <span className={`badge badge-${verdict.toLowerCase()}`}>{verdict}</span>;
}

const STATUS_NAMES: Record<number, string> = { 0: 'NONE', 1: 'ACTIVE', 2: 'REVOKED' };

export function StatusChip({ status }: { status: number }) {
  const name = STATUS_NAMES[status] ?? String(status);
  return <span className={`badge badge-status-${name.toLowerCase()}`}>{name}</span>;
}

export function Bp({ value }: { value: number | null | undefined }) {
  if (value === null || value === undefined) return <span className="muted">—</span>;
  return <span>{(value / 10000).toFixed(4)}</span>;
}

export function Table({ headers, children }: { headers: string[]; children: ReactNode }) {
  return (
    <table>
      <thead>
        <tr>
          {headers.map((h) => (
            <th key={h}>{h}</th>
          ))}
        </tr>
      </thead>
      <tbody>{children}</tbody>
    </table>
  );
}

export function Panel({
  title,
  children,
  actions,
}: {
  title: string;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <section className="panel">
      <header className="panel-header">
        <h2>{title}</h2>
        <div className="actions">{actions}</div>
      </header>
      {children}
    </section>
  );
}

export function ErrorLine({ error }: { error: string | null }) {
  return error ? <p className="error">{error}</p> : null;
}
