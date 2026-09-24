/** Live activity: the gateway's event stream as sentences, newest first (approval console only). */
import { useEffect, useMemo } from 'react';
import { wsUrl } from '../api/client';
import { describeEvent, fmtTime } from '../lib/words';
import { useStore } from '../state/store';

export function Activity() {
  const { logs, connected, addLog, setConnected } = useStore();

  useEffect(() => {
    let socket: WebSocket | null = null;
    let retry: ReturnType<typeof setTimeout> | null = null;
    let closed = false;
    const connect = () => {
      socket = new WebSocket(wsUrl());
      socket.onopen = () => setConnected(true);
      socket.onmessage = (msg) => addLog(JSON.parse(msg.data as string) as Record<string, unknown>);
      socket.onclose = () => {
        setConnected(false);
        if (!closed) retry = setTimeout(connect, 2000);
      };
      socket.onerror = () => socket?.close();
    };
    connect();
    return () => {
      closed = true;
      if (retry) clearTimeout(retry);
      socket?.close();
    };
  }, [addLog, setConnected]);

  const lines = useMemo(
    () =>
      logs
        .map((e) => ({ e, line: describeEvent(e) }))
        .filter(
          (x): x is { e: (typeof logs)[number]; line: NonNullable<typeof x.line> } =>
            x.line !== null,
        )
        .slice(-80)
        .reverse(),
    [logs],
  );

  return (
    <section>
      <h2>
        Live activity <span className={`dot ${connected ? 'on' : 'off'}`} />
      </h2>
      {lines.length === 0 ? (
        <p className="empty small">Waiting for activity. Events appear here as they happen.</p>
      ) : (
        <ol className="activity">
          {lines.map(({ e, line }) => (
            <li key={e.seq} className={line.tone}>
              <time>{fmtTime(e.timestamp)}</time>
              {line.text}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
