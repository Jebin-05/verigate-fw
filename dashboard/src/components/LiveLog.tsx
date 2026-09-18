/** Websocket log stream (P4-06): every structured gateway event, newest at the bottom. */
import { useEffect, useRef } from 'react';
import { wsUrl } from '../api/client';
import { useStore } from '../state/store';

const HIDDEN_KEYS = new Set(['event', 'level', 'timestamp', 'module', 'seq']);

export function LiveLog() {
  const { logs, connected, addLog, setConnected, clearLogs } = useStore();
  const endRef = useRef<HTMLDivElement>(null);

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

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: 'end' });
  }, [logs]);

  return (
    <aside className="livelog">
      <header className="panel-header">
        <h2>
          Live log <span className={connected ? 'dot dot-on' : 'dot dot-off'} />
        </h2>
        <button onClick={clearLogs}>clear</button>
      </header>
      <div className="log-lines">
        {logs.map((line) => (
          <div key={line.seq} className={`log-line level-${line.level ?? 'info'}`}>
            <span className="log-ts">{line.timestamp?.slice(11, 19)}</span>
            <span className="log-event">{line.event}</span>
            {Object.entries(line)
              .filter(([k]) => !HIDDEN_KEYS.has(k))
              .map(([k, v]) => (
                <span key={k} className="log-kv">
                  {k}=<b>{typeof v === 'string' ? v : JSON.stringify(v)}</b>
                </span>
              ))}
          </div>
        ))}
        <div ref={endRef} />
      </div>
    </aside>
  );
}
