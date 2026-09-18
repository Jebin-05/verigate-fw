/** zustand store: live log buffer, websocket status, in-flight attacks. */
import { create } from 'zustand';

export interface LogEvent {
  seq: number;
  timestamp?: string;
  level?: string;
  event?: string;
  [key: string]: unknown;
}

interface State {
  logs: LogEvent[];
  connected: boolean;
  running: string | null;
  addLog: (event: Omit<LogEvent, 'seq'>) => void;
  clearLogs: () => void;
  setConnected: (connected: boolean) => void;
  setRunning: (name: string | null) => void;
}

const MAX_LOGS = 400;
let seq = 0;

export const useStore = create<State>((set) => ({
  logs: [],
  connected: false,
  running: null,
  addLog: (event) =>
    set((s) => ({ logs: [...s.logs.slice(-(MAX_LOGS - 1)), { ...event, seq: seq++ }] })),
  clearLogs: () => set({ logs: [] }),
  setConnected: (connected) => set({ connected }),
  setRunning: (running) => set({ running }),
}));
