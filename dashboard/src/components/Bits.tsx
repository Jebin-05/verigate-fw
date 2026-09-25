/** Shared pieces: verdict badge, id chip, meter, KPI tile, tabs, modal, confirm, time, toasts. */
import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import type { Verdict } from '../api/types';
import { VERDICT_TONE, VERDICT_WORD, fmtDate, type Tone } from '../lib/words';
import { useStore } from '../state/store';

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

/** Shortened identifier; click copies the full value. */
export function Id({ value, chars = 8 }: { value: string | null | undefined; chars?: number }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="faint">—</span>;
  const short =
    value.length > chars + 4 ? `${value.slice(0, chars + 2)}…${value.slice(-3)}` : value;
  const copy = () => {
    navigator.clipboard
      ?.writeText(value)
      .then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1200);
      })
      .catch(() => undefined);
  };
  return (
    <button
      type="button"
      className={`id-chip${copied ? ' copied' : ''}`}
      title={copied ? 'Copied' : `${value}\nClick to copy`}
      onClick={(e) => {
        e.stopPropagation();
        copy();
      }}
    >
      <code className="mono">{copied ? 'Copied' : short}</code>
    </button>
  );
}

/** A date cell: short form visible, the full timestamp on hover. */
export function Time({ iso }: { iso: string | null | undefined }) {
  if (!iso) return <span className="faint">—</span>;
  const d = new Date(iso);
  return (
    <time dateTime={iso} title={isNaN(d.getTime()) ? iso : d.toLocaleString()}>
      {fmtDate(iso)}
    </time>
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

export function Kpi({
  label,
  value,
  sub,
  to,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  /** When set, the tile is a link (e.g. to the filtered list behind the number). */
  to?: string;
}) {
  const body = (
    <>
      <div className="l">{label}</div>
      <div className="v">{value}</div>
      {sub && <div className="s">{sub}</div>}
    </>
  );
  return to ? (
    <Link className="kpi link" to={to} title="Open the list behind this number">
      {body}
    </Link>
  ) : (
    <div className="kpi">{body}</div>
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

/** Dialog: closes on Escape or backdrop click, focuses its first field, locks page scroll. */
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
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    document.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    const el = box.current;
    const first =
      el?.querySelector<HTMLElement>('input:not([type=hidden]), select, textarea') ??
      el?.querySelector<HTMLElement>('.modal-actions button, .panel-b button');
    first?.focus();
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [onClose]);
  return (
    <div className="modal-bg" onClick={onClose}>
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={title}
        ref={box}
        onClick={(e) => e.stopPropagation()}
      >
        <header className="panel-h">
          <h2>{title}</h2>
          <button className="btn-sm" onClick={onClose} aria-label="Close">
            Close
          </button>
        </header>
        <div className="panel-b">{children}</div>
        {actions && <div className="modal-actions">{actions}</div>}
      </div>
    </div>
  );
}

export function Confirm({
  title,
  children,
  confirmLabel = 'Confirm',
  danger = false,
  busy = false,
  onConfirm,
  onCancel,
}: {
  title: string;
  children: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  busy?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  return (
    <Modal
      title={title}
      onClose={onCancel}
      actions={
        <>
          <button type="button" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            type="button"
            className={danger ? 'btn-danger' : 'btn-primary'}
            onClick={onConfirm}
            disabled={busy}
          >
            {busy ? 'Working…' : confirmLabel}
          </button>
        </>
      }
    >
      {children}
    </Modal>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function Loading({ what = '' }: { what?: string }) {
  return <p className="empty loading">{what ? `Loading ${what}…` : 'Loading…'}</p>;
}

export function Toaster() {
  const toasts = useStore((s) => s.toasts);
  const dismiss = useStore((s) => s.dismiss);
  if (toasts.length === 0) return null;
  return (
    <div className="toasts" role="status" aria-live="polite">
      {toasts.map((t) => (
        <div key={t.id} className={`toast ${t.tone}`}>
          <span>{t.text}</span>
          <button type="button" aria-label="Dismiss" onClick={() => dismiss(t.id)}>
            ×
          </button>
        </div>
      ))}
    </div>
  );
}
