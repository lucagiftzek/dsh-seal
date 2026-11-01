// Connection hints (preconnect, dns-prefetch, prerender) open connections to
// other hosts without a fetch the service worker could intercept. These
// helpers remove them from HTML text and Link headers (same rules as the Go
// side, internal/server/hints.go).

export const HINT_RE = /(^|\s)(preconnect|dns-prefetch|prerender)(?=\s|$)/i;
const LINK_TAG = /<link\b[^>]*>/gi;
const REL = /\srel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;
const HREF = /\shref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;

function val(m: RegExpExecArray | null): string {
  return m ? m[1] ?? m[2] ?? m[3] ?? "" : "";
}

/** True when href points at a host other than self (absolute or scheme relative). */
export function foreignHref(href: string, self: string): boolean {
  const m = /^\s*(?:https?:)?\/\/([^/?#]*)/i.exec(href);
  return !!m && m[1].toLowerCase() !== self.toLowerCase();
}

export function neutralizeHintsText(html: string, self: string): string {
  return html.replace(LINK_TAG, (tag) => {
    const rel = val(REL.exec(tag));
    const href = val(HREF.exec(tag));
    if (!HINT_RE.test(rel) || !foreignHref(href, self)) return tag;
    return "<!-- dsh-seal: connection hint removed -->";
  });
}

/** Link header without connecting hints ("" when nothing is left). */
export function hintLinkHeader(v: string): string {
  return v.split(",").map((p) => p.trim()).filter((p) => p && !HINT_RE.test(p.replace(/rel=|"|;/g, " "))).join(", ");
}

const FRAME_TAG = /<(iframe|frame)\b[^>]*>/gi;
const SRC = /\ssrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i;

function escAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/** Placeholder document for a cross-origin frame (see shim.ts). */
export function framePlaceholder(href: string, host: string, dark = false): string {
  const e = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c] as string);
  return `<!doctype html><meta charset="utf-8"><style>html,body{height:100%;margin:0}body{display:flex;align-items:center;justify-content:center;font:13px/1.45 system-ui,sans-serif;background:${dark ? "#1f1d1b" : "#f6f6f6"};color:${dark ? "#ececec" : "#1f1f1f"}}div{max-width:420px;padding:12px;text-align:center}a{color:inherit}</style><div><b>External content not loaded</b><br>${e(host)} would connect outside the encrypted channel.<br><a href="${e(href)}" target="_blank" rel="noopener noreferrer">Open in a new tab</a></div>`;
}

/** Cross-origin iframes in HTML text get the placeholder instead of their src. */
export function neutralizeFramesText(html: string, self: string, onBlocked?: (host: string) => void): string {
  return html.replace(FRAME_TAG, (tag) => {
    const m = SRC.exec(tag);
    const src = val(m);
    if (!m || !foreignHref(src, self)) return tag;
    let host = "";
    try { host = new URL(src.startsWith("//") ? "https:" + src : src).host; } catch { return tag; }
    onBlocked?.(host);
    return tag.replace(m[0], ` data-dsh-seal-src="${escAttr(src)}" srcdoc="${escAttr(framePlaceholder(src, host))}"`);
  });
}
