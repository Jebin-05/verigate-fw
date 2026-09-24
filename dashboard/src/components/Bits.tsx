/** Shared pieces: verdict badge, id chip, meter, KPI tile, tabs, modal, empty state. */
import type { ReactNode } from 'react';
import type { Verdict } from '../api/types';
import { VERDICT_TONE, VERDICT_WORD, type Tone } from '../lib/words';

export function Stamp({
  verdict,
  revoked = false,
  big = false,
}: {
  verdict: Verdict | null | undefined;
  revoked?: boolean;
  big?: boolean;
}) {
  const size = big ? ' big' : '';
  if (revoked) return <span className={`stamp none${size}`}>Withdrawn</span>;
  if (!verdict) return <span className={`stamp none${size}`}>Pending</span>;
  return <span className={`stamp ${VERDICT_TONE[verdict]}${size}`}>{VERDICT_WORD[verdict]}</span>;
}

export function Id({ value, chars = 8 }: { value: string | null | undefined; chars?: number }) {
  if (!value) return <span className="faint">—</span>;
  const short =
    value.length > chars + 4 ? `${value.slice(0, chars + 2)}…${value.slice(-3)}` : value;
  return (
    <code className="mono" title={value}>
      {short}
    </code>
  );
}

export function Meter({
  label,
  value,
  tone = 'none',
  marks = [],
  overall = false,
}: {
  label: string;
  value: number | null | undefined;
  tone?: Tone;
  marks?: { at: number; label: string }[];
  overall?: boolean;
}) {
  const pct = value === null || value === undefined ? 0 : Math.min(100, value / 100);
  return (
    <div className={`meter ${tone}${overall ? ' overall' : ''}`}>
      <span>{label}</span>
      <div className="bar" aria-hidden="true">
        <div className="fill" style={{ width: `${pct}%` }} />
        {marks.map((m) => (
          <div className="mark" key={m.label} style={{ left: `${m.at / 100}%` }}>
            <span>{m.label}</span>
          </div>
        ))}
      </div>
      <span className="num">
        {value === null || value === undefined ? '—' : (value / 10000).toFixed(2)}
      </span>
    </div>
  );
}

export function Kpi({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
  return (
    <div className="kpi">
      <div className="l">{label}</div>
      <div className="v">{value}</div>
      {sub && <div className="s">{sub}</div>}
    </div>
  );
}

export function Panel({
  title,
  actions,
  children,
  flush = false,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  flush?: boolean;
}) {
  return (
    <section className="panel">
      {(title || actions) && (
        <header className="panel-h">
          <h2>{title}</h2>
          {actions && <div className="toolbar">{actions}</div>}
        </header>
      )}
      <div className={`panel-b${flush ? ' flush' : ''}`}>{children}</div>
    </section>
  );
}

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
}: {
  tabs: { id: T; label: string }[];
  value: T;
  onChange: (id: T) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={t.id === value}
          className={t.id === value ? 'active' : ''}
          onClick={() => onChange(t.id)}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

export function Modal({
  title,
  onClose,
  children,
  actions,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  actions?: ReactNode;
}) {
  return (
    <div className="modal-bg" onClick={onClose}>
      <div className="modal" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
        <header className="panel-h">
          <h2>{title}</h2>
          <button className="btn-sm" onClick={onClose}>
            Close
          </button>
        </header>
        <div className="panel-b">{children}</div>
        {actions && <div className="modal-actions">{actions}</div>}
      </div>
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}
