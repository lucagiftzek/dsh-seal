// The page shim for sealed egress (installed by boot.js in the DSH page and in
// every same-origin document the worker serves, e.g. report iframes).
//
// The worker sees every fetch of the page, but some connections never become
// a fetch it could seal: connection hints (preconnect, dns-prefetch,
// prerender), cross-origin iframes (their navigation belongs to the other
// site), beacons, peer connections. This shim closes those doors:
//   - navigator.sendBeacon becomes a fetch (through the worker, so sealed);
//   - link rel=preconnect|dns-prefetch|prerender never take effect (the rel
//     setter and setAttribute are patched; parser-inserted ones are removed);
//   - cross-origin rel=icon is fetched through the worker and set as a blob;
//   - cross-origin iframes get a placeholder with an "Open in a new tab" link
//     (top-level navigation by the user stays direct, as before);
//   - object/embed to other hosts and a[ping] to other hosts are dropped;
//   - RTCPeerConnection and WebTransport are blocked with a console note
//     (their traffic cannot be proxied; egress_webrtc=allow lifts this);
//   - a PerformanceObserver reports any cross-origin resource without worker
//     timing; boot.js asks the worker whether it answered that URL (failed
//     requests carry no worker timing) and counts the rest as "escaped".
// WebSocket and EventSource to other hosts are handled in mux.ts.

import { framePlaceholder, HINT_RE } from "./hints";

export type NoteKind = "egress" | "blocked" | "escaped";
export type Note = (kind: NoteKind, host: string, why: string) => void;

export interface ShimOptions {
  egress: boolean;
  webrtc: string;
  note: Note;
  /** a cross-origin resource with no worker timing: an escape unless the worker says it answered it */
  suspect: (url: string, host: string, why: string) => void;
}

const HINT_G = /(^|\s)(preconnect|dns-prefetch|prerender)(?=\s|$)/gi;

export function installShim(o: ShimOptions) {
  const W = window as any;
  const selfOrigin = location.origin;
  const foreign = (href: string | null | undefined): URL | null => {
    if (!href) return null;
    try {
      const u = new URL(href, document.baseURI);
      return (u.protocol === "http:" || u.protocol === "https:") && u.origin !== selfOrigin ? u : null;
    } catch {
      return null;
    }
  };

  // Escapes: cross-origin resources the worker did not serve.
  const viaWorker = new Set<string>();
  try {
    const po = new PerformanceObserver((list) => {
      for (const e of list.getEntries() as PerformanceResourceTiming[]) {
        const u = foreign(e.name);
        if (!u) continue;
        if (e.workerStart > 0) { viaWorker.add(e.name); continue; }
        if (viaWorker.has(e.name)) continue; // a memory cache reuse of a sealed fetch
        o.suspect(e.name, u.host, e.initiatorType || "resource");
      }
    });
    po.observe({ type: "resource", buffered: true });
  } catch { /* no PerformanceObserver */ }

  if (!o.egress) return; // egress=off: today's behaviour, escapes are only reported

  // Beacons go through the worker.
  const nativeBeacon = typeof navigator.sendBeacon === "function";
  if (nativeBeacon) {
    navigator.sendBeacon = function (url: string | URL, data?: BodyInit | null): boolean {
      try {
        const u = new URL(String(url), location.href);
        const cross = u.origin !== selfOrigin;
        fetch(u.href, { method: "POST", body: data ?? null, mode: cross ? "no-cors" : "same-origin", credentials: cross ? "omit" : "same-origin", cache: "no-store" }).catch(() => {});
        return true;
      } catch {
        return false;
      }
    };
  }

  // Connection hints.
  const nativeSetAttr = Element.prototype.setAttribute;
  const scrubRel = (el: Element, v: string): string => {
    if (!HINT_RE.test(v)) return v;
    const f = foreign(el.getAttribute("href"));
    if (f) o.note("blocked", f.host, "connection hint removed");
    nativeSetAttr.call(el, "data-dsh-seal-rel", v);
    return v.replace(HINT_G, " ").trim() || "dsh-seal-removed";
  };
  const relDesc = Object.getOwnPropertyDescriptor(HTMLLinkElement.prototype, "rel");
  if (relDesc?.set) {
    Object.defineProperty(HTMLLinkElement.prototype, "rel", { ...relDesc, set(v: string) { relDesc.set!.call(this, scrubRel(this, String(v))); } });
  }

  // Cross-origin frames: a placeholder instead of a direct connection.
  const placeholder = (el: HTMLIFrameElement | HTMLFrameElement, u: URL) => {
    nativeSetAttr.call(el, "data-dsh-seal-src", u.href);
    const dark = matchMedia("(prefers-color-scheme: dark)").matches;
    if ("srcdoc" in el) (el as HTMLIFrameElement).srcdoc = framePlaceholder(u.href, u.host, dark);
  };
  const blockFrame = (el: Element, v: string): boolean => {
    const f = foreign(v);
    if (!f) return false;
    o.note("blocked", f.host, "iframe");
    placeholder(el as HTMLIFrameElement, f);
    return true;
  };
  for (const C of [HTMLIFrameElement, (W as any).HTMLFrameElement].filter(Boolean)) {
    const d = Object.getOwnPropertyDescriptor(C.prototype, "src");
    if (d?.set) {
      Object.defineProperty(C.prototype, "src", { ...d, set(v: string) { if (blockFrame(this, String(v))) return; d.set!.call(this, v); } });
    }
  }

  Element.prototype.setAttribute = function (name: string, value: string) {
    const n = String(name).toLowerCase();
    if (n === "rel" && this instanceof HTMLLinkElement) value = scrubRel(this, String(value));
    else if (n === "src" && (this instanceof HTMLIFrameElement || this.tagName === "FRAME")) {
      if (blockFrame(this, String(value))) return;
    } else if ((n === "data" && this instanceof HTMLObjectElement) || (n === "src" && this instanceof HTMLEmbedElement)) {
      const f = foreign(String(value));
      if (f) { o.note("blocked", f.host, this.tagName.toLowerCase()); return; }
    } else if (n === "ping" && this instanceof HTMLAnchorElement) {
      const f = String(value).split(/\s+/).map((x) => foreign(x)).find(Boolean);
      if (f) return;
    }
    return nativeSetAttr.call(this, name, value);
  };

  // Elements the parser or innerHTML created: clean up after the fact.
  const icons = new WeakSet<Element>();
  const check = (el: Element) => {
    if (el instanceof HTMLLinkElement) {
      const f = foreign(el.getAttribute("href"));
      const rel = el.getAttribute("rel") || "";
      if (f && HINT_RE.test(rel)) {
        o.note("blocked", f.host, "connection hint removed");
        el.remove();
      } else if (f && /(^|\s)icon(\s|$)/i.test(rel) && !icons.has(el)) {
        icons.add(el);
        fetch(f.href, { mode: "no-cors", credentials: "omit" }).then((r) => r.blob()).then((b) => {
          if (b.size) nativeSetAttr.call(el, "href", URL.createObjectURL(b));
        }).catch(() => {});
      }
    } else if (el instanceof HTMLIFrameElement || el.tagName === "FRAME") {
      const src = el.getAttribute("src");
      if (src && !el.hasAttribute("data-dsh-seal-src")) {
        const f = foreign(src);
        if (f) {
          o.note("blocked", f.host, "iframe");
          el.removeAttribute("src");
          placeholder(el as HTMLIFrameElement, f);
        }
      }
    } else if (el instanceof HTMLObjectElement || el instanceof HTMLEmbedElement) {
      const f = foreign(el.getAttribute(el instanceof HTMLObjectElement ? "data" : "src"));
      if (f) { o.note("blocked", f.host, el.tagName.toLowerCase()); el.remove(); }
    } else if (el instanceof HTMLAnchorElement && el.hasAttribute("ping")) {
      el.removeAttribute("ping");
    }
  };
  const SEL = "link[href],iframe[src],frame[src],object[data],embed[src],a[ping]";
  const scan = (root: Element | Document) => {
    if (root instanceof Element && root.matches(SEL)) check(root);
    root.querySelectorAll?.(SEL).forEach(check);
  };
  new MutationObserver((muts) => {
    for (const m of muts) {
      if (m.type === "attributes") { if (m.target instanceof Element) check(m.target); continue; }
      m.addedNodes.forEach((n) => { if (n instanceof Element) scan(n); });
    }
  }).observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["rel", "href", "src", "data", "ping"] });
  scan(document);
  document.addEventListener("DOMContentLoaded", () => scan(document), { once: true });

  // Peer connections cannot ride the sealed channel: block them.
  if (o.webrtc !== "allow") {
    for (const name of ["RTCPeerConnection", "webkitRTCPeerConnection", "WebTransport"]) {
      const N = W[name];
      if (typeof N !== "function") continue;
      const label = name === "WebTransport" ? "webtransport" : "webrtc";
      const Blocked = function () {
        console.warn("dsh-seal: " + name + " is blocked: its traffic would go to other hosts directly, outside the encrypted channel. dsh-phone works with server audio; an administrator can set egress_webrtc=allow.");
        o.note("blocked", label, name + " blocked");
        throw new DOMException(name + " is blocked by dsh-seal (sealed egress)", "NotAllowedError");
      } as any;
      Blocked.prototype = N.prototype;
      for (const k of Object.getOwnPropertyNames(N)) {
        if (!(k in Blocked)) { try { Blocked[k] = N[k]; } catch { /* read only */ } }
      }
      Object.defineProperty(Blocked, "name", { value: name });
      W[name] = Blocked;
    }
  }
}
