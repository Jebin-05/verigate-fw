/** Live activity feed list (newest first). */
import { fmtTime } from '../lib/words';
import { useActivity } from '../state/activity';

export function ActivityFeed({ limit = 40 }: { limit?: number }) {
  const { lines } = useActivity(limit);
  if (lines.length === 0) {
    return <p className="empty">No activity yet. Events appear here as they happen.</p>;
  }
  return (
    <ol className="feed">
      {lines.map(({ e, line }) => (
        <li key={e.seq} className={line.tone}>
          <time>{fmtTime(e.timestamp)}</time>
          <span>
            <span className="dot" />
            {line.text}
          </span>
        </li>
      ))}
    </ol>
  );
}
