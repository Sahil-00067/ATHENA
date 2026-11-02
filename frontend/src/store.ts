import { useSyncExternalStore } from "react";

export type View = "city" | "predict" | "path" | "fix" | "lab" | "defend" | "live" | "zeroday" | "proof" | "safety" | "how" | "why";

export interface State {
  token: string | null; user: string | null; role: string | null;
  st: any; geo: any; snap: any; ana: any; exp: any;
  view: View; selected: string | null; hovered: string | null;
  layers: Record<string, boolean>; stack: boolean; xray: boolean;
  hist: { t: number; cs?: number; line?: number; raw?: number; p: number; live: number; none: number; iso: number }[];
  toast: { id: number; sev: string; text: string } | null;
  judge: number | null; pathSel: any; connected: boolean; quality: number; booting: boolean; safetyTab: "certin" | "security";
  labNodes: string[]; labStart: string | null; follow: boolean; pick: "entry" | "goal" | null; atkEntry: string; atkGoal: string; marks: { t: number; label: string; wall: number; before?: number; after?: number }[]; focus: any | null; side: boolean; full: boolean; graph: boolean; blast: boolean; paused: boolean;
}

const init: State = {
  token: sessionStorage.getItem("decoy_token"), user: sessionStorage.getItem("decoy_user"), role: sessionStorage.getItem("decoy_role"),
  st: null, geo: null, snap: null, ana: null, exp: null, view: "city", selected: null, hovered: null,
  layers: { links: true, risk: false }, stack: false, xray: false, hist: [], toast: null, judge: null, pathSel: null, connected: false, quality: 2, booting: true, safetyTab: "certin", labNodes: [], labStart: null, follow: false, pick: null, atkEntry: "", atkGoal: "", marks: [], focus: null, side: false, full: false, graph: false, blast: true, paused: false,
};

let state = init;
const subs = new Set<() => void>();
export const getState = () => state;
export const setState = (p: Partial<State> | ((s: State) => Partial<State>)) => { state = { ...state, ...(typeof p === "function" ? p(state) : p) }; subs.forEach((f) => f()); };
export function useStore<T>(sel: (s: State) => T): T {
  return useSyncExternalStore((cb) => { subs.add(cb); return () => subs.delete(cb); }, () => sel(state));
}

let toastId = 0, toastTimer: any = null;
/** One small message at a time, in a corner of the map, for 3 s. Automatic events never pop up. */
export const toast = (sev: string, text: string) => {
  const id = ++toastId; setState({ toast: { id, sev, text } });
  clearTimeout(toastTimer); toastTimer = setTimeout(() => setState((s) => (s.toast?.id === id ? { toast: null } : {})), 3000);
};
