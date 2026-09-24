/** Activity: the full live event log as a table. */
import { useActivity } from '../../state/activity';
import { Empty, Panel } from '../../components/Bits';
import { fmtTime } from '../../lib/words';
import { useStore } from '../../state/store';

export function ActivityPage() {
  const { lines, connected } = useActivity(400);
  const clearLogs = useStore((s) => s.clearLogs);
  return (
    <Panel
      title={
        <>
          Live activity <span className={`dot ${connected ? 'on' : 'off'}`} />
        </>
      }
      flush
      actions={
        <button className="btn-sm" onClick={clearLogs}>
          Clear
        </button>
      }
    >
      {lines.length === 0 ? (
        <Empty>Waiting for events from the gateway.</Empty>
      ) : (
        <table className="data">
          <thead>
            <tr>
              <th style={{ width: 90 }}>Time</th>
              <th style={{ width: 90 }}>Kind</th>
              <th>Event</th>
            </tr>
          </thead>
          <tbody>
            {lines.map(({ e, line }) => (
              <tr key={e.seq}>
                <td className="muted">{fmtTime(e.timestamp)}</td>
                <td>
                  <span className={`stamp ${line.tone}`}>
                    {line.tone === 'ok'
                      ? 'ok'
                      : line.tone === 'warn'
                        ? 'attention'
                        : line.tone === 'bad'
                          ? 'refused'
                          : 'info'}
                  </span>
                </td>
                <td className="wrap">{line.text}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
