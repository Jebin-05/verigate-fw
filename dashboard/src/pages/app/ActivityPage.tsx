/** Activity: the full live event log as a table. */
import { Link } from 'react-router-dom';
import { useActivity } from '../../state/activity';
import { Empty, Panel } from '../../components/Bits';
import { fmtTime } from '../../lib/words';
import { useStore } from '../../state/store';

const KIND: Record<string, string> = { ok: 'ok', warn: 'attention', bad: 'refused', none: 'info' };

export function ActivityPage() {
  const { lines, connected } = useActivity(400);
  const clearLogs = useStore((s) => s.clearLogs);
  return (
    <Panel
      title={
        <>
          Live activity{' '}
          <span
            className={`dot ${connected ? 'on' : 'off'}`}
            title={connected ? 'Receiving events' : 'Reconnecting'}
          />
        </>
      }
      flush
      actions={
        <button className="btn-sm" onClick={clearLogs} disabled={lines.length === 0}>
          Clear
        </button>
      }
    >
      {lines.length === 0 ? (
        <Empty>
          {connected ? 'No events since this page was opened.' : 'Connecting to the gateway…'}
        </Empty>
      ) : (
        <table className="data">
          <thead>
            <tr>
              <th style={{ width: 90 }}>Time</th>
              <th style={{ width: 90 }}>Kind</th>
              <th>Event</th>
              <th style={{ width: 70 }}></th>
            </tr>
          </thead>
          <tbody>
            {lines.map(({ e, line }) => (
              <tr key={e.seq}>
                <td className="muted">{fmtTime(e.timestamp)}</td>
                <td>
                  <span className={`stamp ${line.tone}`}>{KIND[line.tone]}</span>
                </td>
                <td className="wrap">{line.text}</td>
                <td>
                  {line.releaseId && (
                    <Link className="small" to={`/app/releases?r=${line.releaseId}`}>
                      Open
                    </Link>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
