/** Websocket log stream → readable lines (hook). Lives outside component files for fast refresh. */
import { useEffect, useMemo } from 'react';
import { wsUrl } from '../api/client';
import { describeEvent, type Line } from '../lib/words';
import { useStore, type LogEvent } from './store';

export interface ActivityLine {
  e: LogEvent;
  line: Line;
}

/** Keeps the websocket open while mounted and returns the readable lines, newest first. */
export function useActivity(limit = 80): { lines: ActivityLine[]; connected: boolean } {
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
        .filter((x): x is ActivityLine => x.line !== null)
        .slice(-limit)
        .reverse(),
    [logs, limit],
  );
  return { lines, connected };
}
