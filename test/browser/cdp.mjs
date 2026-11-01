// Minimal flattened CDP client for the real-browser checks: one browser-level
// WebSocket, sessions for the test page, its frames/workers and the sealing
// service worker. Every request seen by any session is recorded (URLs with a
// token are redacted). Only targets of the test origin are touched.
export async function connect({ cdp = "http://127.0.0.1:9222", origin, headers }) {
  const ver = await (await fetch(cdp + "/json/version")).json();
  const ws = new WebSocket(ver.webSocketDebuggerUrl);
  await new Promise((ok, bad) => { ws.onopen = ok; ws.onerror = () => bad(new Error("cdp ws error")); });
  let id = 0;
  const pending = new Map();
  const handlers = [];
  const log = []; // {t, sid, kind, type, method, url, fromSW, status}
  const reqs = new Map();
  const sessions = new Map(); // sid -> {type,url}
  const ours = new Set();
  const consoleLines = [];
  const redact = (u) => String(u).replace(/token=[A-Za-z0-9_-]+/g, "token=<redacted>");
  const send = (method, params = {}, sessionId) => new Promise((ok, bad) => {
    const i = ++id;
    const timer = setTimeout(() => { pending.delete(i); bad(new Error(method + " timed out")); }, 30000);
    pending.set(i, (d) => { clearTimeout(timer); d.error ? bad(new Error(method + ": " + d.error.message)) : ok(d.result); });
    ws.send(JSON.stringify(sessionId ? { id: i, method, params, sessionId } : { id: i, method, params }));
  });
  async function prepare(sid, info) {
    sessions.set(sid, info);
    await send("Network.enable", {}, sid).catch(() => {});
    if (headers) await send("Network.setExtraHTTPHeaders", { headers }, sid).catch(() => {});
    await send("Runtime.enable", {}, sid).catch(() => {});
    if (info.type === "page" || info.type === "iframe") {
      await send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }, sid).catch(() => {});
    }
    await send("Runtime.runIfWaitingForDebugger", {}, sid).catch(() => {});
  }
  ws.onmessage = async (m) => {
    const d = JSON.parse(m.data);
    if (d.id && pending.has(d.id)) { pending.get(d.id)(d); pending.delete(d.id); return; }
    const p = d.params || {};
    if (d.method === "Target.attachedToTarget") {
      const ti = p.targetInfo;
      if (ours.has(ti.targetId) && ti.type === "page" && !sessions.size) return; // our own attach, prepared below
      if (ours.has(ti.targetId) || ti.url.startsWith(origin) || ti.type === "iframe" || ti.type === "worker") {
        prepare(p.sessionId, { type: ti.type, url: redact(ti.url) });
      } else {
        // not ours (another agent's target): let it run and let go of it
        send("Runtime.runIfWaitingForDebugger", {}, p.sessionId).catch(() => {});
        send("Target.detachFromTarget", { sessionId: p.sessionId }).catch(() => {});
      }
      return;
    }
    const sid = d.sessionId || "";
    if (d.method === "Network.requestWillBeSent") {
      const e = { t: Date.now(), sid, kind: sessions.get(sid)?.type || "?", type: p.type, method: p.request.method, url: redact(p.request.url), fromSW: false, status: 0 };
      reqs.set(sid + p.requestId, e);
      log.push(e);
    } else if (d.method === "Network.responseReceived") {
      const e = reqs.get(sid + p.requestId);
      if (e) { e.fromSW = !!p.response.fromServiceWorker; e.status = p.response.status; e.fromCache = !!p.response.fromDiskCache; }
    } else if (d.method === "Network.webSocketCreated") {
      log.push({ t: Date.now(), sid, kind: sessions.get(sid)?.type || "?", type: "WebSocket", method: "GET", url: redact(p.url), fromSW: false, status: 101 });
    } else if (d.method === "Network.webSocketFrameReceived") {
      log.push({ t: Date.now(), sid, kind: "wsframe", type: "frame", len: p.response.payloadData.length, ts: p.timestamp });
    } else if (d.method === "Runtime.consoleAPICalled") {
      consoleLines.push(p.type + " " + redact(p.args.map((a) => a.value ?? a.description ?? "").join(" ").slice(0, 300)));
    } else if (d.method === "Runtime.exceptionThrown") {
      consoleLines.push("exception " + redact((p.exceptionDetails.exception?.description || p.exceptionDetails.text || "").slice(0, 300)));
    }
    if (process.env.CDP_DEBUG && /^(Target|Page.frame|Network.loadingFailed|Inspector)/.test(d.method || "")) console.log("evt", d.method, JSON.stringify(p).replace(/token=[A-Za-z0-9_-]+/g, "token=<r>").slice(0, 200));
    for (const h of handlers) h(d);
  };
  // service workers of our origin are separate top-level targets
  await send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: false, flatten: true, filter: [{ type: "service_worker", exclude: false }, { exclude: true }] });
  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  ours.add(targetId);
  let page;
  try {
    ({ sessionId: page } = await send("Target.attachToTarget", { targetId, flatten: true }));
    await prepare(page, { type: "page", url: "about:blank" });
    await send("Page.enable", {}, page);
    await send("Emulation.setDeviceMetricsOverride", { width: 1500, height: 950, deviceScaleFactor: 1, mobile: false }, page);
  } catch (e) {
    await send("Target.closeTarget", { targetId }).catch(() => {});
    ws.close();
    throw e;
  }
  const evaluate = async (expression, ms = 15000) => {
    const r = await Promise.race([send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true }, page), new Promise((_, bad) => setTimeout(() => bad(new Error("evaluate timeout")), ms))]);
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  };
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const shot = async (file) => {
    const fs = await import("node:fs");
    const r = await send("Page.captureScreenshot", { format: "png" }, page);
    fs.writeFileSync(file, Buffer.from(r.data, "base64"), { mode: 0o600 });
  };
  const mouse = async (x, y) => {
    for (const type of ["mouseMoved", "mousePressed", "mouseReleased"]) await send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: type === "mouseMoved" ? 0 : 1 }, page);
  };
  const key = async (k, code = k, vk = 0) => {
    await send("Input.dispatchKeyEvent", { type: "keyDown", key: k, code, windowsVirtualKeyCode: vk }, page);
    await send("Input.dispatchKeyEvent", { type: "keyUp", key: k, code, windowsVirtualKeyCode: vk }, page);
  };
  const close = async () => {
    try { await send("Target.closeTarget", { targetId }); } catch { /* already gone */ }
    try { await send("Target.setAutoAttach", { autoAttach: false, waitForDebuggerOnStart: false, flatten: true }); } catch { /* ignore */ }
    try { ws.close(); } catch { /* ignore */ }
  };
  return { send, page, targetId, evaluate, sleep, shot, mouse, key, close, log, consoleLines, sessions, handlers };
}
