/** Compact live feed for the Overview: newest first, each line opens its release when it has one. */
import { Link } from 'react-router-dom';
import { fmtTime } from '../lib/words';
import { useActivity } from '../state/activity';

export function ActivityFeed({ limit = 40 }: { limit?: number }) {
  const { lines } = useActivity(limit);
  if (lines.length === 0) {
    return <p className="empty">No activity yet.</p>;
  }
  return (
    <ol className="feed">
      {lines.map(({ e, line }) => (
        <li key={e.seq} className={line.tone}>
          <time>{fmtTime(e.timestamp)}</time>
          <span>
            <span className="dot" />
            {line.releaseId ? (
              <Link to={`/app/releases?r=${line.releaseId}`} title="Open this release">
                {line.text}
              </Link>
            ) : (
              line.text
            )}
          </span>
        </li>
      ))}
    </ol>
  );
}
