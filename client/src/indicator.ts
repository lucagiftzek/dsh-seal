// The seal status indicator: always visible, in the last
// row of the DSH sidebar footer, right aligned in the empty space right of
// "... More". A pixel art lock plus one word in the style of "More":
//
//   sealed   closed lock   "Encrypted"
//   plain    open lock     "Detectable" (plain right now; the reason is in the tooltip)
//   warning  broken lock   "Broken"     (server key changed)
//
// The lock shows the CURRENT state: after a fallback (laptop sleep, network
// change) it returns to Encrypted once the sealed path works again; the
// popover keeps the history ("Earlier") and the counters since page load.
// Click or Enter opens a small popover with the details. In the collapsed
// sidebar only the lock is shown, under the account button. The footer
// re-renders, so a MutationObserver re-mounts it (idempotent); without the
// footer it floats in the bottom right corner. It lives in a shadow root, so
// page styles do not leak in either direction; colours follow the theme.
// dsh-session-pin's "Pinned sessions" footer button stays hidden (the rail hides it;
// the workspace rail hides it too).

export interface IndicatorStatus {
  state: string; // "starting" | "sealed" | "plain" | "warning"
  reason: string;
  mode: string;
  fingerprint: string;
  fallbacks: number;
  swFallbacks?: number;
  sealedRequests?: number;
  sealedChannels?: number;
  sessionAt?: number;
  egress?: boolean;
  view?: { egress: Record<string, number>; blocked: Record<string, string>; escaped: Record<string, string> };
  /** what happened earlier in this page view ("3 requests went plain at 17:18 (SEAL_MUX_CONNECT)") */
  history?: string[];
  /** the sealed socket right now (connected, reconnecting, waiting for the network) */
  link?: string;
  failedRequests?: number;
}

// 14 x 16 pixel art, drawn with rects (crisp edges), like the theme's pixel type.
const ART: Record<string, string[]> = {
  sealed: [
    "..............", "..............", "....######....", "...########...", "...##....##...", "...##....##...", "...##....##...", "...##....##...",
    ".############.", ".############.", ".#####..#####.", ".#####..#####.", ".#####..#####.", ".############.", ".############.", ".############.",
  ],
  plain: [
    "....######....", "...########...", "...##....##...", "...##....##...", "...##.........", "...##.........", "...##.........", "...##.........",
    ".############.", ".############.", ".#####..#####.", ".#####..#####.", ".#####..#####.", ".############.", ".############.", ".############.",
  ],
  warning: [
    "..............", "........###...", "....###.###...", "...####...##..", "...##.....##..", "...##....##...", "...##....##...", "...##....##...",
    ".######.#####.", ".######.#####.", ".#####.######.", ".#####.######.", ".######.#####.", ".######.#####.", ".#####.######.", ".#####.######.",
  ],
};
function pixelSvg(rows: string[]): string {
  let rects = "";
  rows.forEach((row, y) => {
    for (let x = 0; x < row.length; ) {
      if (row[x] !== "#") { x++; continue; }
      let w = 0;
      while (row[x + w] === "#") w++;
      rects += `<rect x="${x}" y="${y}" width="${w}" height="1"/>`;
      x += w;
    }
  });
  return `<svg viewBox="0 0 14 16" width="14" height="16" shape-rendering="crispEdges" fill="currentColor" aria-hidden="true" focusable="false">${rects}</svg>`;
}
const ICON: Record<string, string> = { sealed: pixelSvg(ART.sealed), plain: pixelSvg(ART.plain), warning: pixelSvg(ART.warning) };
const WORD: Record<string, string> = { sealed: "Encrypted", plain: "Detectable", warning: "Broken" };
const LABEL: Record<string, string> = { sealed: "Encrypted", plain: "Not encrypted, detectable", warning: "Broken: server key changed" };

const PIN_BUTTON = "button.__dsh-session-pin-footer__";
const ACCOUNT = 'button[aria-label="Account menu"]';
const STYLE_ID = "dsh-seal-indicator-style";

// Page level CSS (outside the shadow root): the "Pinned sessions" footer button
// is hidden, and the footer's last row becomes a flex row so the indicator
// takes the free space right of "... More" instead of covering it.
const PAGE_CSS = `${PIN_BUTTON}{display:none!important}
[data-dsh-seal-row]{display:flex!important;align-items:center;gap:4px}
[data-dsh-seal-row]>:not(dsh-seal-status){flex:1 1 auto;min-width:0}
[data-dsh-seal-row]>:not(dsh-seal-status)>button{width:100%}
[data-dsh-seal-row][data-dsh-seal-compact]{flex-direction:column;gap:2px}`;

const CSS = `
:host{all:initial;display:inline-flex;align-items:center;flex:0 0 auto;vertical-align:middle}
:host(.floating){position:fixed;right:10px;bottom:10px;z-index:2147483646}
.b{box-sizing:border-box;display:inline-flex;align-items:center;gap:6px;height:28px;padding:0 6px;margin:0;border:0;border-radius:var(--r,0);background:transparent;cursor:pointer;color:var(--fg);font:var(--font);letter-spacing:var(--ls,normal);white-space:nowrap}
.b .i{display:inline-flex;color:var(--c);line-height:0}
.b svg{width:14px;height:16px}
:host(.compact) .b{padding:0;width:36px;height:28px;justify-content:center}
:host(.compact) .w{display:none}
:host(.floating) .b{background:var(--pbg);box-shadow:0 1px 3px rgba(0,0,0,.3)}
.b:hover{background:var(--hover)}
.b:focus-visible{outline:2px solid var(--focus,#4c8dff);outline-offset:1px}
.pop{position:fixed;z-index:2147483647;max-height:min(70vh,520px);overflow:auto;min-width:240px;max-width:min(320px,calc(100vw - 16px));padding:10px 12px;border-radius:var(--r,0);border:1px solid var(--pb);background:var(--pbg);color:var(--pfg);box-shadow:var(--shadow,0 6px 24px rgba(0,0,0,.3));font:12px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;text-align:left}
.pop[hidden]{display:none}
.pop h2{display:flex;align-items:center;gap:6px;margin:0 0 6px;font-size:13px;font-weight:600}
.pop h2 .i{color:var(--c);line-height:0}
.pop dl{display:grid;grid-template-columns:auto 1fr;gap:2px 10px;margin:0}
.pop dt{opacity:.7}.pop dd{margin:0;word-break:break-word}
.pop code{font:11px ui-monospace,SFMono-Regular,Menlo,monospace}
.pop .note{margin:8px 0 0;opacity:.75}
`;

function age(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return s + " s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + " min";
  return Math.floor(m / 60) + " h " + (m % 60) + " min";
}

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c] as string);
}

/** Dark page? Read from the page background, so it follows the DSH theme. */
export function darkPage(): boolean {
  const bgs = [document.body, document.documentElement].map((e) => (e ? getComputedStyle(e).backgroundColor : ""));
  const bg = bgs.find((c) => c && !/rgba\(0, 0, 0, 0\)|transparent/.test(c)) || "";
  const m = bg.match(/\d+(\.\d+)?/g);
  if (!m) return matchMedia("(prefers-color-scheme: dark)").matches;
  const [r, g, b] = m.map(Number);
  return 0.2126 * r + 0.7152 * g + 0.0722 * b < 128;
}

export class Indicator {
  readonly host: HTMLElement;
  private root: ShadowRoot;
  private btn: HTMLButtonElement;
  private pop: HTMLElement;
  private lastState = "";
  private since = Date.now();
  private queued = false;
  placement: "footer" | "floating" | "none" = "none";

  constructor(private st: IndicatorStatus, private refresh: () => Promise<void>) {
    this.host = document.createElement("dsh-seal-status");
    this.host.id = "dsh-seal-badge";
    this.root = this.host.attachShadow({ mode: "open" });
    this.root.innerHTML = `<style>${CSS}</style><button class="b" type="button" aria-haspopup="dialog" aria-expanded="false"></button><div class="pop" role="dialog" aria-label="Encryption status" hidden></div>`;
    this.btn = this.root.querySelector("button") as HTMLButtonElement;
    this.pop = this.root.querySelector(".pop") as HTMLElement;
    this.btn.addEventListener("click", (e) => { e.stopPropagation(); this.toggle(); });
    this.root.addEventListener("keydown", (e: Event) => {
      if ((e as KeyboardEvent).key === "Escape" && !this.pop.hidden) { this.close(); this.btn.focus(); }
    });
    document.addEventListener("click", (e) => { if (!this.pop.hidden && !e.composedPath().includes(this.host)) this.close(); }, true);
    addEventListener("resize", () => { this.queue(); if (!this.pop.hidden) this.placePop(); });
    const start = () => {
      this.update();
      new MutationObserver(() => this.queue()).observe(document.body, { childList: true, subtree: true });
      setInterval(() => this.queue(), 3000);
    };
    if (document.body) start();
    else document.addEventListener("DOMContentLoaded", start, { once: true });
  }

  private queue() {
    if (this.queued) return;
    this.queued = true;
    setTimeout(() => { this.queued = false; this.mount(); }, 150);
  }

  /** Put the indicator in the footer's last row, right of "... More" (idempotent). */
  private mount() {
    if (this.st.state === "starting") return;
    const acc = ([...document.querySelectorAll(ACCOUNT)] as HTMLElement[]).find((e) => e.getBoundingClientRect().width > 0) || null;
    const anchor = acc?.parentElement || null;
    const row = anchor?.parentElement || null;
    for (const old of document.querySelectorAll("[data-dsh-seal-row]")) if (old !== row) { old.removeAttribute("data-dsh-seal-row"); old.removeAttribute("data-dsh-seal-compact"); }
    if (acc && anchor && row && row !== document.body) {
      const compact = acc.getAttribute("data-collapsed") === "true" || acc.getBoundingClientRect().width < 80;
      if (!row.hasAttribute("data-dsh-seal-row")) row.setAttribute("data-dsh-seal-row", "");
      if (compact) row.setAttribute("data-dsh-seal-compact", ""); else row.removeAttribute("data-dsh-seal-compact");
      if (row.lastElementChild !== this.host) row.appendChild(this.host);
      this.host.classList.toggle("compact", compact);
      this.setPlacement("footer", acc);
    } else {
      this.host.classList.remove("compact");
      if (this.host.parentElement !== document.body) document.body.appendChild(this.host);
      this.setPlacement("floating", null);
    }
    if (!document.getElementById(STYLE_ID) && document.head) {
      const st = document.createElement("style");
      st.id = STYLE_ID;
      st.textContent = PAGE_CSS;
      document.head.appendChild(st);
    }
  }

  private setPlacement(p: "footer" | "floating", ref: HTMLElement | null) {
    this.placement = p;
    this.host.classList.toggle("floating", p === "floating");
    this.host.dataset.placement = p;
    // the word takes the font and colour of "More"
    const src = (ref?.querySelector("span:not(:empty)") as HTMLElement | null) || ref;
    if (src) {
      const cs = getComputedStyle(src);
      this.host.style.setProperty("--font", cs.fontStyle + " " + cs.fontWeight + " " + cs.fontSize + "/" + "20px " + cs.fontFamily);
      this.host.style.setProperty("--fg", cs.color);
      this.host.style.setProperty("--ls", cs.letterSpacing);
      this.host.style.setProperty("--r", getComputedStyle(ref as HTMLElement).borderRadius || "0");
    } else {
      this.host.style.setProperty("--font", '14px/20px system-ui,-apple-system,"Segoe UI",sans-serif');
    }
    this.colours();
  }

  private colours() {
    const dark = darkPage();
    const kind = this.kind();
    const c = kind === "sealed" ? (dark ? "#3fb950" : "#1a7f37") : kind === "warning" ? (dark ? "#ff6b61" : "#cf222e") : (dark ? "#9da5ae" : "#57606a");
    const s = this.host.style;
    s.setProperty("--c", c);
    s.setProperty("--hover", dark ? "rgba(255,255,255,.08)" : "rgba(0,0,0,.06)");
    s.setProperty("--pbg", dark ? "#1f1d1b" : "#ffffff");
    s.setProperty("--pfg", dark ? "#ececec" : "#1f1f1f");
    s.setProperty("--pb", dark ? "#3c3a38" : "#d0d0d0");
  }

  private kind(): string {
    return this.st.state === "sealed" ? "sealed" : this.st.state === "warning" ? "warning" : "plain";
  }

  /** Redraw after a state change. */
  update() {
    const st = this.st;
    if (st.state === "starting") return;
    if (st.state !== this.lastState) {
      this.lastState = st.state;
      this.since = Date.now();
    }
    const kind = this.kind();
    this.host.dataset.state = kind;
    this.btn.innerHTML = '<span class="i">' + ICON[kind] + '</span><span class="w">' + WORD[kind] + "</span>";
    const tip = LABEL[kind] + (kind === "sealed" ? ": traffic to the DSH server is sealed" : st.reason ? " (" + st.reason + ")" : "");
    this.btn.title = tip;
    this.btn.setAttribute("aria-label", tip + ". Show encryption details");
    this.colours();
    this.mount();
    if (!this.pop.hidden) this.fill();
  }

  private placePop() {
    const r = this.btn.getBoundingClientRect();
    const p = this.pop.getBoundingClientRect();
    const left = Math.min(Math.max(8, r.left), innerWidth - p.width - 8);
    const above = r.top - p.height - 6;
    this.pop.style.left = left + "px";
    this.pop.style.top = (above >= 8 ? above : Math.min(r.bottom + 6, innerHeight - p.height - 8)) + "px";
  }

  private fill() {
    const st = this.st;
    const kind = this.kind();
    const rows: [string, string][] = [["State", esc(LABEL[kind])]];
    if (st.reason) rows.push(["Reason", esc(st.reason)]);
    rows.push(["Since", esc(new Date(this.since).toLocaleTimeString())]);
    if (st.link) rows.push(["Link", esc(st.link)]);
    rows.push(["Session age", st.sessionAt ? esc(age(Date.now() - st.sessionAt)) : "no session"]);
    rows.push(["Sealed requests", String(st.sealedRequests ?? 0) + " (plus " + String(st.sealedChannels ?? 0) + " sockets and streams)"]);
    rows.push(["Fallbacks", String((st.fallbacks || 0) + (st.swFallbacks || 0)) + " since the page loaded"]);
    if (st.failedRequests) rows.push(["Failed", esc(st.failedRequests + " (network errors, not resent in plain)")]);
    if (st.history?.length) rows.push(["Earlier", st.history.map((h) => esc(h)).join("<br>")]);
    const v = st.view || { egress: {}, blocked: {}, escaped: {} };
    const list = (items: string[]) => items.map((s) => "<br><code>" + esc(s) + "</code>").join("");
    if (st.egress) {
      const hosts = Object.entries(v.egress).sort((a, b) => b[1] - a[1]);
      const n = hosts.reduce((s, [, c]) => s + c, 0);
      rows.push(["Other hosts", n ? esc(n + " requests to " + hosts.length + " hosts, fetched by the server") + list(hosts.slice(0, 8).map(([h, c]) => h + " (" + c + ")")) + (hosts.length > 8 ? esc(" and " + (hosts.length - 8) + " more") : "") : "none so far (they would go through the server)"]);
    } else rows.push(["Other hosts", "direct (egress off)"]);
    const bl = Object.entries(v.blocked);
    if (bl.length) rows.push(["Blocked", list(bl.slice(0, 8).map(([h, w]) => h + ": " + w)).slice(4) + (bl.length > 8 ? esc(" and " + (bl.length - 8) + " more") : "")]);
    const es = Object.entries(v.escaped);
    if (es.length) rows.push(["Escaped", list(es.slice(0, 8).map(([h, w]) => h + ": " + w)).slice(4) + (es.length > 8 ? esc(" and " + (es.length - 8) + " more") : "")]);
    rows.push(["Server key", "<code>" + esc((st.fingerprint || "").slice(0, 16)) + "</code>"]);
    rows.push(["Mode", esc(st.mode)]);
    const note = kind === "warning"
      ? "The server key differs from the one this browser trusted and no signed rotation leads to it. Treat this as an incident."
      : kind === "sealed"
        ? (st.egress
          ? "Requests travel encrypted inside HTTPS to the DSH server, which also fetches other hosts for this page: they see the server, not this device. An observer on the way sees only volume and timing."
          : "Requests travel encrypted inside HTTPS to the DSH server; an observer on the way sees only volume and timing.")
        : Object.keys(v.escaped).length ? "Some connections of this page view went to other hosts directly (listed under Escaped)." : "Some requests of this page view use plain HTTPS.";
    this.pop.innerHTML = `<h2><span class="i">${ICON[kind]}</span><span>dsh-seal: ${WORD[kind]}</span></h2><dl>${rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join("")}</dl><p class="note">${esc(note)}</p>`;
  }

  private async toggle() {
    if (!this.pop.hidden) { this.close(); return; }
    this.colours();
    this.fill();
    this.pop.hidden = false;
    this.btn.setAttribute("aria-expanded", "true");
    this.placePop();
    try { await this.refresh(); } catch { /* keep the last values */ }
    if (!this.pop.hidden) { this.fill(); this.placePop(); }
  }

  private close() {
    this.pop.hidden = true;
    this.btn.setAttribute("aria-expanded", "false");
  }
}
