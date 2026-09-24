/** Small shared pieces: the verdict stamp, an id chip, a labelled meter, an empty state. */
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
  if (!verdict) return <span className={`stamp none${size}`}>Not yet inspected</span>;
  return (
    <span className={`stamp ${VERDICT_TONE[verdict]}${size}`} key={verdict}>
      {VERDICT_WORD[verdict]}
    </span>
  );
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
  value: number | null | undefined; // basis points
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

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}
