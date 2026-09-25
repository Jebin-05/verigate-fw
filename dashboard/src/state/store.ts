/** zustand store: live log buffer, websocket status, in-flight attacks, toasts. */
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

export interface Toast {
  id: number;
  text: string;
  tone: 'ok' | 'bad' | 'none';
}

interface State {
  logs: LogEvent[];
  connected: boolean;
  running: string | null;
  sim: Sim | null; // rules simulator (Governance) — affects how verdicts are displayed only
  toasts: Toast[];
  addLog: (event: Omit<LogEvent, 'seq'>) => void;
  clearLogs: () => void;
  setConnected: (connected: boolean) => void;
  setRunning: (name: string | null) => void;
  setSim: (sim: Sim | null) => void;
  toast: (text: string, tone?: Toast['tone']) => void;
  dismiss: (id: number) => void;
}

const MAX_LOGS = 400;
let seq = 0;
let toastSeq = 0;

export const useStore = create<State>((set) => ({
  logs: [],
  connected: false,
  running: null,
  sim: null,
  toasts: [],
  addLog: (event) =>
    set((s) => ({ logs: [...s.logs.slice(-(MAX_LOGS - 1)), { ...event, seq: seq++ }] })),
  clearLogs: () => set({ logs: [] }),
  setConnected: (connected) => set({ connected }),
  setRunning: (running) => set({ running }),
  setSim: (sim) => set({ sim }),
  toast: (text, tone = 'none') => {
    const id = ++toastSeq;
    set((s) => ({ toasts: [...s.toasts, { id, text, tone }] }));
    setTimeout(() => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), 5000);
  },
  dismiss: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));

/** Stable selector for firing a toast from any component. */
export function useToast(): (text: string, tone?: Toast['tone']) => void {
  return useStore((s) => s.toast);
}

/** Two stable selectors (zustand v5 re-renders on a fresh object every time). */
export function useSim(): { sim: Sim | null; setSim: (sim: Sim | null) => void } {
  const sim = useStore((s) => s.sim);
  const setSim = useStore((s) => s.setSim);
  return { sim, setSim };
}
