// boot.js: injected by dsh-seal as the first element of <head>. It runs
// before any DSH script: it makes sure the sealing service worker controls the
// page, patches WebSocket and EventSource onto the sealed mux (same-origin and,
// with sealed egress, other hosts too), installs the egress shim (shim.ts) and
// publishes window.__dshSeal = { state: "sealed" | "plain" | "warning" | "starting", reason }.
//
// Frame mode (/_s/boot.js?f=1, injected by the worker into same-origin
// documents such as report iframes): sockets, shim and counters only; no
// indicator, no reload, no cookie. The top page merges the counters of its
// same-origin frames.

import { establish, IDBKV, SealConfig, SealError, SEALED_ONLY_KEY, Session } from "./seal";
import { makeSealedEventSource, makeSealedWebSocket, Mux, Upgradable } from "./mux";
import { Indicator } from "./indicator";
import { installShim, NoteKind } from "./shim";
import { browserEnv, NetHealth, transientCode } from "./net";
import { decide, historyLines, pushEvent, SealEvent } from "./state";

declare const self: any;

type HostMap = Record<string, number>;
type WhyMap = Record<string, string>;

(function boot() {
  const W = window as any;
  if (W.__dshSeal) return; // injected twice (should not happen): keep the first
  const conf: SealConfig = self.__DSH_SEAL_CFG;
  const cfg = conf.cfg;
  const frame = /[?&]f=1(&|$)/.test((document.currentScript as HTMLScriptElement | null)?.src || "");
  const egressOn = !!cfg.egress;
  const status: any = {
    state: "starting",
    reason: "",
    version: cfg.version,
    mode: cfg.mode,
    egress: egressOn,
    frame,
    fingerprint: conf.bundle.fp,
    sw: "pending",
    mux: "idle",
    fallbacks: 0,
    sealedOnly: !!cfg.sealedOnly,
    // what this document's shim saw (sockets, hints, frames, peer connections, escapes)
    egressHosts: {} as HostMap,
    blocked: {} as WhyMap,
    escaped: {} as WhyMap,
    // merged view (worker counters of this page and of its frames + the above)
    view: { egress: {} as HostMap, blocked: {} as WhyMap, escaped: {} as WhyMap },
    escapedAt: {} as HostMap,
    // what happened earlier in this page view (popover history)
    events: [] as SealEvent[],
    history: [] as string[],
    link: "",
  };
  W.__dshSeal = status;

  const supported = !!(window.isSecureContext && globalThis.crypto?.subtle && "serviceWorker" in navigator && window.indexedDB);
  const NativeWS = window.WebSocket;
  const NativeES = window.EventSource;
  let kv: IDBKV | null = null;
  let sessP: Promise<Session> | null = null;
  let mux: Mux | null = null;
  let warning = false;
  // plain sockets and event streams that move back onto the seal once it works again
  const natives = new Set<Upgradable>();
  let lastPlainAt = 0; // last socket of this page that went plain
  let lastHealthyAt = 0; // last time the page's mux connected

  function isShell(p: string) {
    return cfg.shell.some((s) => (s.endsWith("*") ? p.startsWith(s.slice(0, -1)) : p === s));
  }
  function shouldSeal(u: URL) {
    return !u.pathname.startsWith("/_s/") && !cfg.exclude.some((x) => u.pathname.startsWith(x));
  }
  function fallbackAllowed() {
    return !status.sealedOnly && !warning;
  }
  function onFallback(why: string) {
    status.fallbacks++;
    status.lastFallback = why;
    lastPlainAt = Date.now();
    pushEvent(status.events, { t: lastPlainAt, kind: "plain", why });
    if (status.state === "sealed") { status.state = "plain"; status.reason = "fallback: " + why; badge(); }
    scheduleUpgrade();
  }
  let upgradeTimer: any = null;
  function upgradeNatives() {
    for (const n of [...natives]) n.upgrade("seal restored");
  }
  // While sockets are plain, keep trying the seal; when it works, move them back.
  function scheduleUpgrade() {
    if (upgradeTimer) return;
    upgradeTimer = setInterval(() => {
      if (!natives.size) { clearInterval(upgradeTimer); upgradeTimer = null; return; }
      if (document.hidden || !navigator.onLine || !mux) return;
      if (mux.state === "open") upgradeNatives();
      else mux.warm().catch(() => {});
    }, 15000);
  }

  // Egress notes from the shim and the socket classes.
  function put(m: any, host: string, v: any) {
    if (host in m || Object.keys(m).length < 64) m[host] = v;
  }
  function note(kind: NoteKind, host: string, why: string) {
    if (kind === "egress") put(status.egressHosts, host, (status.egressHosts[host] || 0) + 1);
    else if (!(host in status[kind])) put(status[kind], host, why);
    if (kind === "escaped") {
      status.escapedAt[host] = Date.now();
      pushEvent(status.events, { t: Date.now(), kind: "escaped", why: host + ": " + why });
    }
    if (frame) {
      try { if (parent !== window) (parent as any).__dshSeal?.note?.(kind, host, why); } catch { /* cross-origin parent */ }
      return;
    }
    if (kind === "egress") return;
    merge(null);
    if (kind === "escaped" && status.state === "sealed") { status.state = "plain"; status.reason = "escaped: " + host; }
    badge();
  }
  status.note = note;

  function getSession(fresh: boolean): Promise<Session> {
    if (!sessP || fresh) {
      sessP = establish(conf, kv!, (i, init) => fetch(i, init), location.origin).catch((e) => {
        sessP = null;
        // a fetch that threw during the handshake: the network, not the seal
        if (!(e instanceof SealError)) e = new SealError("SEAL_NETWORK", String(e?.message || e), 0, true);
        if (e instanceof SealError && e.code === "SEAL_TOFU_MISMATCH") {
          warning = true;
          status.state = "warning";
          status.reason = e.code;
          badge();
        }
        throw e;
      });
    }
    return sessP;
  }

  // The always visible status indicator (square lock in the sidebar footer).
  let indicator: Indicator | null = null;
  function badge() {
    if (frame || status.state === "starting") return;
    if (!indicator) indicator = new Indicator(status, async () => { await status.check?.(); });
    indicator.update();
  }

  if (!frame) {
    // Mark this browser as having the seal client (the server then serves the
    // real shell instead of the bootstrap page). The cookie only says that.
    document.cookie = "sealboot=1; path=/; max-age=31536000; SameSite=Lax" + (location.protocol === "https:" ? "; Secure" : "");
  }
  const bootstrap = !frame && !!document.querySelector("meta[name=dsh-seal-bootstrap]");
  if (!supported) {
    status.state = "plain";
    status.reason = "unsupported";
    if (bootstrap) location.reload();
    else badge();
    return;
  }

  // The worker must control the top page before DSH loads, or the page's
  // requests go out plain. A HARD reload (Shift reload, Cmd+Shift+R, Ctrl+F5)
  // bypasses the worker for that page view by design of every browser. Cure:
  // stop the page before any DSH code runs and do a NORMAL reload, which the
  // worker controls. The server also answers a hard reload of the shell with
  // the bootstrap page (boot.js only), so not even DSH's assets load plain.
  // Loop guard per tab: at most 2 automatic reloads in 30 s; after that the
  // page runs, asks the worker to claim it, and the lock says why.
  const RELOADS = "dsh-seal-reloads";
  const secure = location.protocol === "https:" ? "; Secure" : "";
  const recentReloads = (): number[] => {
    try {
      return (JSON.parse(sessionStorage.getItem(RELOADS) || "[]") as number[]).filter((t) => Date.now() - t < 30000);
    } catch {
      return [0, 0]; // no sessionStorage: never loop
    }
  };
  const reloadControlled = (why: string) => {
    try {
      const a = recentReloads();
      a.push(Date.now());
      sessionStorage.setItem(RELOADS, JSON.stringify(a));
    } catch { /* counted as given up next time */ }
    // tells the server: this reload must get the real shell (even with no-cache)
    document.cookie = "sealhr=1; path=/; max-age=30; SameSite=Lax" + secure;
    status.reason = why;
    location.reload();
  };
  const sw = navigator.serviceWorker;
  if (!frame && sw.controller) {
    try { sessionStorage.removeItem(RELOADS); } catch { /* ignore */ }
    if (document.cookie.includes("sealhr=")) document.cookie = "sealhr=; path=/; max-age=0; SameSite=Lax" + secure;
  }
  if (bootstrap) {
    // The server held the DSH shell back until the worker is in control
    // (first visit, or a hard reload).
    status.reason = "installing";
    const tries = recentReloads().length;
    const go = () => (tries >= 2 ? setTimeout(() => reloadControlled("installing"), 3000) : reloadControlled("installing"));
    if (sw.controller) { go(); return; }
    sw.addEventListener("controllerchange", go, { once: true });
    sw.getRegistration("/").then((reg) => {
      if (reg?.active) { go(); return; } // hard reload: the worker is there, a normal reload is controlled
      sw.register("/_s/sw.js", { scope: "/", updateViaCache: "none" })
        .then(() => setTimeout(go, 8000))
        .catch(() => setTimeout(go, 100));
    }, () => setTimeout(go, 100));
    return;
  }
  kv = new IDBKV();

  if (frame) {
    if (!sw.controller) status.sw = "not-controlling";
  } else if (!sw.controller) {
    if (recentReloads().length < 2) {
      // Stop parsing now (nothing of DSH has run), then reload under the worker.
      window.stop();
      status.reason = "installing";
      sw.addEventListener("controllerchange", () => reloadControlled("installing"), { once: true });
      sw.getRegistration("/").then((reg) => {
        if (reg?.active) { reloadControlled("hard reload"); return; }
        sw.register("/_s/sw.js", { scope: "/", updateViaCache: "none" })
          .then(() => setTimeout(() => reloadControlled("installing"), 8000))
          .catch((e) => {
            status.state = "plain";
            status.reason = "sw-register: " + (e?.message || e);
            setTimeout(() => reloadControlled("installing"), 100);
          });
      }, () => setTimeout(() => reloadControlled("installing"), 100));
      return;
    }
    // Two reloads in 30 s did not give control (worker missing, broken or
    // bypassed): run, and ask an active worker to claim this page (second line
    // of defence); until then fetches of this page view are plain.
    status.sw = "not-controlling";
    status.gaveUp = true;
    pushEvent(status.events, { t: Date.now(), kind: "uncontrolled", why: "worker not in control after 2 reloads" });
    sw.register("/_s/sw.js", { scope: "/", updateViaCache: "none" })
      .then((reg) => (reg.active || reg.installing || reg.waiting)?.postMessage({ t: "dsh-seal-claim" }))
      .catch(() => {});
    sw.addEventListener("controllerchange", () => {
      lastPlainAt = Date.now(); // plain until now
      status.check?.();
    });
  } else {
    sw.register("/_s/sw.js", { scope: "/", updateViaCache: "none" }).catch(() => {});
  }

  const wsBase = (location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/_s/ws";
  // Network health: reconnect, wait while offline or asleep, fall back only
  // after the grace window with the network demonstrably up.
  const net = new NetHealth(browserEnv("/_s/p"));
  mux = new Mux(getSession, wsBase, (u) => new NativeWS(u), {
    net,
    onState: (st) => {
      status.mux = st;
      if (st === "open") {
        lastHealthyAt = Date.now();
        if (natives.size) upgradeNatives();
        if (!frame && status.state !== "starting") status.check?.();
      }
    },
  });
  net.on((ev) => { if (!frame && (ev === "online" || ev === "visible" || ev === "resume")) setTimeout(() => status.check?.(), 1500); });
  const getMux = () => mux;
  const SWS = makeSealedWebSocket(NativeWS, getMux, shouldSeal, fallbackAllowed, onFallback, () => egressOn, note, natives);
  const SES = makeSealedEventSource(NativeES, getMux, shouldSeal, fallbackAllowed, onFallback, () => egressOn, note, natives);
  for (const [S, N] of [[SWS, NativeWS], [SES, NativeES]] as [any, any][]) {
    Object.defineProperty(S, Symbol.hasInstance, { value: (x: unknown) => x instanceof N || Object.prototype.isPrototypeOf.call(S.prototype, x as object) });
    Object.defineProperty(S, "name", { value: N.name });
  }
  W.WebSocket = SWS;
  W.EventSource = SES;

  // Escape candidates are confirmed against the worker's list of URLs it answered.
  let suspects: { url: string; host: string; why: string }[] = [];
  let verifyTimer: any = null;
  function settle(r: any) {
    const handled = new Set<string>(r?.handled || []);
    const s = suspects;
    suspects = [];
    for (const x of s) if (!handled.has(x.url) && !handled.has(x.url.split("#")[0])) note("escaped", x.host, x.why);
  }
  function suspect(url: string, host: string, why: string) {
    if (suspects.length < 200) suspects.push({ url, host, why });
    clearTimeout(verifyTimer);
    verifyTimer = setTimeout(() => { if (frame) swStatus().then(settle, () => settle(null)); else check(); }, 1500);
  }
  installShim({ egress: egressOn, webrtc: cfg.webrtc || "block", note, suspect });

  // The worker's counters for this document.
  async function swStatus(): Promise<any> {
    if (!sw.controller) return { ok: false, reason: "not-controlling" };
    const ch = new MessageChannel();
    const reply = new Promise<any>((res) => {
      ch.port1.onmessage = (e) => res(e.data);
      setTimeout(() => res({ ok: false, reason: "timeout" }), 10000);
    });
    sw.controller.postMessage({ t: "dsh-seal-status" }, [ch.port2]);
    return reply;
  }
  status.swStatus = swStatus;

  // Merge worker counters (this page and its same-origin frames) with the notes.
  function merge(parts: any[] | null) {
    if (parts) status.swParts = parts;
    const v = { egress: {} as HostMap, blocked: {} as WhyMap, escaped: {} as WhyMap };
    for (const p of [...(status.swParts || []), { egress: status.egressHosts, blocked: status.blocked, escaped: status.escaped }]) {
      for (const [h, n] of Object.entries(p?.egress || {})) put(v.egress, h, (v.egress[h] || 0) + (n as number));
      for (const [h, w] of Object.entries(p?.blocked || {})) if (!(h in v.blocked)) put(v.blocked, h, w);
      for (const [h, w] of Object.entries(p?.escaped || {})) if (!(h in v.escaped)) put(v.escaped, h, w);
    }
    status.view = v;
  }
  async function frameParts(doc: Document, depth: number, out: any[]) {
    if (depth > 3) return;
    for (const f of Array.from(doc.querySelectorAll("iframe, frame"))) {
      try {
        const w = (f as HTMLIFrameElement).contentWindow as any;
        const fs = w?.__dshSeal;
        if (fs?.frame && fs.swStatus) {
          out.push(await Promise.race([fs.swStatus(), new Promise((r) => setTimeout(() => r(null), 3000))]));
          await frameParts(w.document, depth + 1, out);
        }
      } catch { /* cross-origin or gone */ }
    }
  }

  if (frame) return;

  // Status: the page session and the worker session must both be live, and
  // nothing may have escaped.
  async function check() {
    try {
      const only = await kv!.get(SEALED_ONLY_KEY);
      if (only === "1") status.sealedOnly = true;
      const sess = await getSession(false);
      status.sessionAt = sess.created;
      status.sealedChannels = mux?.channelsOpened || 0;
      let swOk = false;
      if (sw.controller) {
        const r = await swStatus();
        settle(r);
        status.sw = r.ok ? "sealed" : "plain: " + r.reason;
        // offline or a restart in the path: the worker waits, nothing goes plain
        swOk = !!r.ok || transientCode(String(r.reason || ""));
        if (typeof r.sealed === "number") status.sealedRequests = r.sealed;
        if (typeof r.pageFallbacks === "number") status.swFallbacks = r.pageFallbacks;
        if (r.lastFallback) status.lastFallback = r.lastFallback;
        if (r.reason === "SEAL_TOFU_MISMATCH") warning = true;
        const parts = [r];
        await frameParts(document, 0, parts);
        merge(parts.filter(Boolean));
      } else merge([]);
      // the CURRENT state; what happened earlier stays in the popover history
      const parts: any[] = status.swParts || [];
      const escapedAt: HostMap = { ...status.escapedAt };
      const escapedWhy: WhyMap = { ...status.view.escaped };
      const events: SealEvent[] = [...status.events];
      let swPlainAt = 0, swHealthyAt = 0, fallbackMode = false, egressOff = false, failed = 0;
      for (const p of parts) {
        if (!p) continue;
        for (const [h, t] of Object.entries(p.escapedAt || {})) escapedAt[h] = Math.max(escapedAt[h] || 0, t as number);
        for (const e of p.events || []) events.push(e);
        swPlainAt = Math.max(swPlainAt, p.lastPlainAt || 0);
        swHealthyAt = Math.max(swHealthyAt, p.lastHealthyAt || 0);
        fallbackMode = fallbackMode || !!p.fallbackMode;
        egressOff = egressOff || !!p.egressOff;
        failed += p.failed || 0;
      }
      status.failedRequests = failed;
      const d = decide({
        now: Date.now(), warning, controlled: !!sw.controller, swOk, swReason: String(status.sw).replace(/^plain: /, ""),
        nativeLive: natives.size, swFallbackMode: fallbackMode,
        lastPlainAt: Math.max(lastPlainAt, swPlainAt), lastHealthyAt: Math.max(lastHealthyAt, swHealthyAt),
        egressOff, escapedAt, escapedWhy,
      });
      status.state = d.state;
      status.reason = d.reason;
      if (status.gaveUp && !sw.controller) status.reason += " (2 reloads did not give the worker control)";
      events.sort((a, b) => a.t - b.t);
      status.history = historyLines(events);
      status.link = !navigator.onLine ? "offline, waiting (nothing goes plain)" : mux?.state === "waiting" ? "waiting for the network" : mux?.state === "connecting" ? "reconnecting" : mux?.state === "open" ? "connected" : "idle (opens with the first socket)";
    } catch (e: any) {
      if (e instanceof SealError && transientCode(e.code)) {
        // offline or the server restarting: nothing went plain, keep the state
        status.link = "waiting for the network (" + e.code + ")";
      } else {
        status.state = warning ? "warning" : "plain";
        status.reason = e?.code || String(e);
      }
    }
    badge();
  }
  status.check = check;
  status.redraw = () => badge();
  status.setSealedOnly = async (on: boolean) => {
    await kv!.set(SEALED_ONLY_KEY, on ? "1" : "0");
    status.sealedOnly = on || !!cfg.sealedOnly;
    sw.controller?.postMessage({ t: "dsh-seal-sealed-only", on });
  };
  Object.defineProperty(status, "muxState", { get: () => mux?.state, enumerable: true });
  check();
  // keep the indicator current (state and counters) without user action
  setInterval(() => { if (!document.hidden && !status.frozen) check(); }, 30000);
})();
