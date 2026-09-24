/** zustand store: live log buffer, websocket status, in-flight attacks. */
import { create } from 'zustand';

export interface LogEvent {
  seq: number;
  timestamp?: string;
  level?: string;
  event?: string;
  [key: string]: unknown;
}

export interface Sim {
  approve: number;
  reject: number;
}

interface State {
  logs: LogEvent[];
  connected: boolean;
  running: string | null;
  sim: Sim | null; // rules simulator (Governance) — affects how verdicts are displayed only
  addLog: (event: Omit<LogEvent, 'seq'>) => void;
  clearLogs: () => void;
  setConnected: (connected: boolean) => void;
  setRunning: (name: string | null) => void;
  setSim: (sim: Sim | null) => void;
}

const MAX_LOGS = 400;
let seq = 0;

export const useStore = create<State>((set) => ({
  logs: [],
  connected: false,
  running: null,
  sim: null,
  addLog: (event) =>
    set((s) => ({ logs: [...s.logs.slice(-(MAX_LOGS - 1)), { ...event, seq: seq++ }] })),
  clearLogs: () => set({ logs: [] }),
  setConnected: (connected) => set({ connected }),
  setRunning: (running) => set({ running }),
  setSim: (sim) => set({ sim }),
}));

/** Two stable selectors (zustand v5 re-renders on a fresh object every time). */
export function useSim(): { sim: Sim | null; setSim: (sim: Sim | null) => void } {
  const sim = useStore((s) => s.sim);
  const setSim = useStore((s) => s.setSim);
  return { sim, setSim };
}
