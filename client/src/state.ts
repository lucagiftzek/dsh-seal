// What the lock shows: the CURRENT state. A plain
// fallback or an escape earlier in the page view stays in the popover
// history ("Earlier: ..."), but once the sealed path is healthy again the lock
// is back to Encrypted. A condition that is still going on (the page is not
// controlled by the worker, a socket is still open in plain, the worker is in
// fallback mode, egress is off and hosts go direct) keeps it Detectable.

export type EventKind = "plain" | "escaped" | "failed" | "uncontrolled";

/** One thing that happened to this page view, for the history. */
export interface SealEvent {
  t: number; // ms since the epoch
  kind: EventKind;
  why: string;
  n?: number;
}

/** An escape is "current" for this long after it happened. */
export const ESCAPE_RECENT_MS = 5 * 60 * 1000;

export interface Inputs {
  now: number;
  warning: boolean;
  controlled: boolean; // the worker controls the page
  swOk: boolean; // the worker has a sealed session
  swReason: string;
  nativeLive: number; // sockets or event streams still open in plain
  swFallbackMode: boolean; // the worker is falling back right now (grace expired)
  lastPlainAt: number; // last request or socket that went plain
  lastHealthyAt: number; // last proof the sealed path works (sealed answer, mux open)
  egressOff: boolean;
  escapedAt: Record<string, number>; // host -> last time it went out directly
  escapedWhy: Record<string, string>;
}

export function decide(i: Inputs): { state: string; reason: string } {
  if (i.warning) return { state: "warning", reason: "SEAL_TOFU_MISMATCH" };
  if (!i.controlled) return { state: "plain", reason: "worker: not-controlling" };
  if (!i.swOk) return { state: "plain", reason: "worker: " + (i.swReason || "no sealed session") };
  if (i.nativeLive > 0) return { state: "plain", reason: "fallback: " + i.nativeLive + (i.nativeLive === 1 ? " socket is" : " sockets are") + " still plain" };
  if (i.swFallbackMode) return { state: "plain", reason: "fallback: the sealed path is failing, requests go plain" };
  if (i.lastPlainAt && i.lastPlainAt >= i.lastHealthyAt) return { state: "plain", reason: "fallback: requests went plain, the sealed path has not recovered yet" };
  const current = Object.keys(i.escapedAt).filter((h) => i.egressOff || i.now - i.escapedAt[h] < ESCAPE_RECENT_MS);
  if (current.length) {
    return { state: "plain", reason: "escaped: " + current.slice(0, 3).map((h) => h + (i.escapedWhy[h] ? " (" + i.escapedWhy[h] + ")" : "")).join(", ") + (current.length > 3 ? " and " + (current.length - 3) + " more" : "") };
  }
  return { state: "sealed", reason: "" };
}

function hhmm(t: number): string {
  const d = new Date(t);
  return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
}

/**
 * History lines for the popover, oldest first, grouped per minute, kind and
 * reason: "3 requests went plain at 17:18 (SEAL_MUX_CONNECT)".
 */
export function historyLines(events: SealEvent[], max = 6): string[] {
  const groups = new Map<string, { t: number; kind: EventKind; why: string; n: number }>();
  for (const e of [...events].sort((a, b) => a.t - b.t)) {
    const k = hhmm(e.t) + "|" + e.kind + "|" + e.why;
    const g = groups.get(k);
    if (g) g.n += e.n || 1;
    else groups.set(k, { t: e.t, kind: e.kind, why: e.why, n: e.n || 1 });
  }
  const lines = [...groups.values()].map((g) => {
    const at = " at " + hhmm(g.t) + (g.why ? " (" + g.why + ")" : "");
    switch (g.kind) {
      case "plain": return g.n + (g.n === 1 ? " request went plain" : " requests went plain") + at;
      case "escaped": return g.n + (g.n === 1 ? " connection went direct" : " connections went direct") + at;
      case "failed": return g.n + (g.n === 1 ? " request failed (not resent in plain)" : " requests failed (not resent in plain)") + at;
      default: return "page not controlled by the worker" + at;
    }
  });
  return lines.length > max ? [...lines.slice(0, 1), "...", ...lines.slice(-(max - 2))] : lines;
}

/** Keep an event list bounded (merged events of one page view). */
export function pushEvent(list: SealEvent[], e: SealEvent, cap = 200) {
  const last = list[list.length - 1];
  if (last && last.kind === e.kind && last.why === e.why && e.t - last.t < 60000) {
    last.n = (last.n || 1) + (e.n || 1);
    return;
  }
  list.push(e);
  if (list.length > cap) list.splice(0, list.length - cap);
}
