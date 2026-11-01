// Screenshots of the seal status indicator: three states (sealed, plain,
// warning) x light and dark x desktop and phone width, plus the popover opened
// with the keyboard. Checks that the lock overlaps no other control.
//   node indicator-shots.mjs [base] [outdir]
// Light is simulated in this page only (body without data-ds-dark-theme), so
// the account's theme setting is never changed.
import { connect } from "./cdp.mjs";
import { writeFileSync } from "node:fs";

const base = process.argv[2] || "http://127.0.0.4:3083";
const out = process.argv[3] || "/var/tmp/seal-work/pre/indicator";
const c = await connect({ origin: base });
const deadline = setTimeout(async () => { console.log("FAIL deadline"); await c.close(); process.exit(1); }, 300000);
const res = {};
const clipShot = async (file, clip) => {
  const r = await c.send("Page.captureScreenshot", { format: "png", clip: { ...clip, scale: 1 } }, c.page);
  writeFileSync(file, Buffer.from(r.data, "base64"), { mode: 0o600 });
};
const info = () => c.evaluate(`(() => {
  const h = document.getElementById('dsh-seal-badge'); if (!h) return null;
  const b = h.shadowRoot.querySelector('button'); const r = b.getBoundingClientRect();
  const hits = [...document.querySelectorAll('button,[role=button],a,input')].filter(e => !h.contains(e) && e.offsetParent !== null).map(e => [e, e.getBoundingClientRect()])
    .filter(([e, q]) => q.width && q.height && q.left < r.right - 1 && q.right > r.left + 1 && q.top < r.bottom - 1 && q.bottom > r.top + 1)
    .map(([e]) => (e.getAttribute('aria-label') || e.title || e.innerText || e.tagName).trim().slice(0, 40));
  const pin = document.querySelector('button.__dsh-session-pin-footer__');
  const u = [...document.querySelectorAll('button[aria-label="Account menu"]')].find(e => e.getBoundingClientRect().width > 0); const ur = u && u.getBoundingClientRect();
  const top = document.elementFromPoint(r.x + r.width / 2, r.y + r.height / 2);
  return { onTop: top === h, focused: document.activeElement === h && h.shadowRoot.activeElement === b, placement: h.dataset.placement, state: h.dataset.state, rect: [r.x, r.y, r.width, r.height].map(Math.round), account: ur && [ur.x, ur.y, ur.width, ur.height].map(Math.round), word: b.innerText, overlaps: hits, label: b.getAttribute('aria-label'), title: b.title, pinVisible: !!(pin && pin.offsetParent !== null), color: getComputedStyle(b).color };
})()`);
try {
  await c.send("Page.navigate", { url: base + "/" }, c.page);
  for (let i = 0; i < 60; i++) {
    await c.sleep(1000);
    const st = await c.evaluate("window.__dshSeal && __dshSeal.state").catch(() => null);
    if (st && st !== "starting") break;
  }
  await c.sleep(6000);
  res.real = await c.evaluate("({state: __dshSeal.state, reason: __dshSeal.reason, sealedRequests: __dshSeal.sealedRequests, sealedChannels: __dshSeal.sealedChannels})");
  // collapse check: right after load the state is real (sealed)
  for (const [vw, w, h] of [["desktop", 1500, 950], ["phone", 390, 844]]) {
    await c.send("Emulation.setDeviceMetricsOverride", { width: w, height: h, deviceScaleFactor: 1, mobile: w < 600 }, c.page);
    await c.sleep(2500);
    for (const theme of ["dark", "light"]) {
      await c.evaluate(theme === "light"
        ? "(() => { document.body.removeAttribute('data-ds-dark-theme'); document.documentElement.dataset.dsThemeSource = 'light'; document.documentElement.style.colorScheme = 'light' })()"
        : "(() => { document.body.setAttribute('data-ds-dark-theme', ''); document.documentElement.dataset.dsThemeSource = 'dark'; document.documentElement.style.colorScheme = 'dark' })()");
      for (const state of ["sealed", "plain", "warning"]) {
        const reason = state === "plain" ? "fallback: 1 requests went plain (test)" : state === "warning" ? "SEAL_TOFU_MISMATCH" : "";
        await c.evaluate(`(() => { __dshSeal.frozen = true; document.activeElement && document.activeElement.blur && document.activeElement.blur(); __dshSeal.state = ${JSON.stringify(state)}; __dshSeal.reason = ${JSON.stringify(reason)}; __dshSeal.redraw() })()`);
        await c.sleep(700);
        const i = await info();
        const key = `${vw}-${theme}-${state}`;
        res[key] = i;
        if (i) {
          const x = 0, y = Math.max(0, i.rect[1] - 90);
          await clipShot(`${out}-${key}.png`, { x, y, width: Math.min(w, 300), height: Math.min(h - y, 130) });
        }
      }
      // popover through the keyboard (focus + Enter), sealed state
      await c.evaluate("(() => { __dshSeal.state = 'sealed'; __dshSeal.reason = ''; __dshSeal.redraw(); document.getElementById('dsh-seal-badge').shadowRoot.querySelector('button').focus() })()");
      await c.send("Input.dispatchKeyEvent", { type: "keyDown", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" }, c.page);
      await c.send("Input.dispatchKeyEvent", { type: "keyUp", key: "Enter", code: "Enter", windowsVirtualKeyCode: 13 }, c.page);
      await c.sleep(1500);
      res[`${vw}-${theme}-popover`] = await c.evaluate("(() => { const p = document.getElementById('dsh-seal-badge').shadowRoot.querySelector('.pop'); const r = p.getBoundingClientRect(); return { open: !p.hidden, rect: [r.x, r.y, r.width, r.height].map(Math.round), text: p.innerText, expanded: document.getElementById('dsh-seal-badge').shadowRoot.querySelector('button').getAttribute('aria-expanded') } })()");
      await c.shot(`${out}-${vw}-${theme}-popover.png`);
      await c.key("Escape", "Escape", 27);
      await c.sleep(400);
      res[`${vw}-${theme}-popover-closed`] = await c.evaluate("document.getElementById('dsh-seal-badge').shadowRoot.querySelector('.pop').hidden");
      await c.shot(`${out}-${vw}-${theme}-full.png`);
    }
  }
  await c.evaluate("(() => { document.body.setAttribute('data-ds-dark-theme', ''); __dshSeal.check() })()");
} catch (e) {
  res.FAIL = e.stack || e.message;
} finally {
  writeFileSync(out + "-evidence.json", JSON.stringify(res, null, 1));
  console.log(JSON.stringify(res, null, 0).slice(0, 6000));
  console.log("console errors", JSON.stringify(c.consoleLines.filter((l) => /^(error|exception)/.test(l)).slice(0, 8)));
  clearTimeout(deadline);
  await c.close();
}
setTimeout(() => process.exit(0), 300);
