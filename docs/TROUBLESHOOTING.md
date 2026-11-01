# dsh-seal troubleshooting

## First aid: take it out of the path

```
scripts/seal-switch.sh off
```

Switches dsh-seal to passthrough (installed service workers see `SEAL_DISABLED` and unregister), then points the reverse proxy back at the upstream (`http://127.0.0.1:3081` in the examples). With the traefik file provider (`SEAL_TRAEFIK_FILE`, service `SEAL_TRAEFIK_SERVICE`) traefik hot-reloads the file; no restart of traefik, the upstream or DSH is needed. By hand: set the backend url back to the upstream. The script keeps backups of that file in `deploy/backup/` (not tracked by git).

Even if dsh-seal is gone without passthrough, browsers recover: a worker that gets a 404 without `X-Seal-Error` from `/_s/x` (`SEAL_ABSENT`) unregisters itself and the request is retried in plain.

## Where to look

| What | Command |
|---|---|
| State, counters, key id | `curl -s 127.0.0.1:3082/_s/health \| jq` |
| Prometheus text | `curl -s 127.0.0.1:3082/_s/metrics` |
| Logs | `journalctl -u dsh-seal -n 100` |
| Routing | `scripts/seal-switch.sh status` |
| In the browser | DevTools console: `__dshSeal` (state, reason, sw, muxState, fallbacks) |
| Fingerprint | `bin/dsh-seal -config deploy/dsh-seal.conf fingerprint` |

## Symptoms

**Lock "Detectable".** The lock shows the CURRENT state (since 0.5.0); `__dshSeal.reason` names the cause and the popover row "Earlier" keeps what happened before in this page view. `fallback: ...` = something is plain right now (a socket still open in plain, the worker in fallback mode, or requests went plain and the sealed path has not answered since). `escaped: ...` = a connection to another host went direct in the last 5 minutes (or egress is off). `worker: not-controlling` = the service worker does not control the page (see "Hard reload" below). `unsupported` = no service workers or WebCrypto (insecure context).

### Hard reload

What the user saw before 0.5.0: after Cmd+Shift+R (or Ctrl+Shift+R, Ctrl+F5, Shift+click on reload) the lock said Detectable, popover "Reason: worker: not-controlling", "Sealed requests 0". Cause: every browser bypasses the service worker for a hard-reloaded page view by design, and the old boot.js reloaded at most once per 15 s, so a hard reload soon after another reload (or after the automatic one) left the page uncontrolled and every DSH request went plain for that page view. Even a "recovered" hard reload let about 6 DSH assets (CSS, plugin bundles) out in plain, fetched by the preload scanner before boot.js could stop the page.

Since 0.5.0 (two layers):

1. **Server**: a shell request with the `sealboot` cookie and the hard reload signature (`Pragma: no-cache` or `Cache-Control: no-cache`) gets the bootstrap page (boot.js only, about 300 bytes, no favicon request) instead of the DSH shell, unless boot.js just asked for the reload (cookie `sealhr`, 30 s). Counter `hard_reload_bootstrap` in `/_s/health`.
2. **Client** (boot.js, first thing in `<head>`): not controlled but the registration has an ACTIVE worker (the hard reload case) = `window.stop()` before any DSH code, set `sealhr`, and a normal `location.reload()`, which the worker controls. Loop guard per tab: at most 2 automatic reloads in 30 s (sessionStorage, cleared by every controlled load); only when the worker stays missing or broken does the page run uncontrolled, ask the worker to claim it (`clients.claim()` on a "dsh-seal-claim" message, also on every activate) and say so in the lock.

What an observer sees per hard reload now: `GET /` (bootstrap page) + `/_s/boot.js`, `GET /` (shell, normal reload) + `/_s/boot.js`, `POST /_s/h`, then only `/_s/x` and `/_s/ws`. Measured with Chrome over CDP (`Page.reload` with `ignoreCache: true`), three identities: sealed and controlled every time, 0 plain DSH requests after the shell. If the no-cache headers do not reach dsh-seal (a proxy that strips them), layer 2 alone still ends sealed, but the preload scanner sends the shell's static assets (about 7 CSS/JS files, no API calls) in plain once.

Browsers: **Chrome/Edge**: Shift reload and Ctrl/Cmd+Shift+R bypass the worker and send `Pragma: no-cache` + `Cache-Control: no-cache`; DevTools "Disable cache" sends no-cache on every load (handled by `sealhr`, no loop), "Bypass for network" in Application, Service workers keeps every load uncontrolled (the lock then says why after 2 reloads). **Firefox**: Ctrl/Cmd+Shift+R and Ctrl+F5 bypass the worker and send `Pragma: no-cache` + `Cache-Control: no-cache`; private windows have no service workers at all ("unsupported", plain). **Safari**: Cmd+Option+R (reload from origin) bypasses the worker and sends `Cache-Control: no-cache` (from WebKit sources and reports; not verified on a real Safari here, layer 2 covers it either way); a plain Cmd+R is a normal reload; Safari evicts service workers of sites unused for weeks, the next visit then gets the bootstrap page once. What to do as a user: nothing; if the lock ever stays "worker: not-controlling", a normal reload (Cmd+R) fixes it.

### Laptop sleep, network change

What the user saw before 0.5.0: after a sleep or a Wi-Fi change the popover said "fallback: 3 requests went plain (last SEAL_MUX_CONNECT)" and the lock stayed Detectable for the rest of the page view, even when everything worked again. Cause: on wake the page's sockets reconnected before the network was back; the mux connect failed at once (close 1006) and the sealed WebSocket/EventSource fell back to plain immediately; the lock never went back.

Since 0.5.0:

- **Mux** (`client/src/mux.ts`): connect retries with exponential backoff and jitter (0.5, 1, 2, 4, 8 s); offline (`navigator.onLine` false, the `offline` event) means "wait", never fail; `online`, `visibilitychange` to visible, `resume` (freeze) and `pageshow` from the bfcache reconnect at once; a keepalive gap far beyond 25 s means the machine slept or the tab was frozen: the socket is checked with a ping and dropped quietly if dead (not a failure); close 4401 (session unknown after a restart or 12 h idle) does a fresh handshake. Sessions survive a dropped mux (server memory, 12 h idle), so a reconnect after a short sleep needs no handshake.
- **Worker fetches** (`/_s/x`): idempotent requests (GET, HEAD, OPTIONS) are retried after a fresh handshake with the same backoff, waiting while offline, up to 35 s; non-idempotent requests that hit a network error are never replayed and never sent plain: they fail visibly (popover "Failed: N (network errors, not resent in plain)"). A restart of dsh-seal (a 502 from the reverse proxy) is retried for every method, because nothing reached DSH.
- **Fallback policy (offer)**: plain only after the sealed path kept failing for 25 s WHILE the network is demonstrably up (a plain `GET /_s/p` gets any answer); offline, a hidden page or a probe that fails never count. Sockets that fell back move back onto the seal automatically once the mux works again (they close with 1006 and their owners reconnect, sealed).
- **Lock**: back to Encrypted once the sealed path answers again; the popover keeps "Earlier: 3 requests went plain at 17:18 (SEAL_MUX_CONNECT)" and the counters since page load. While offline the lock stays Encrypted and the "Link" row says "offline, waiting (nothing goes plain)".
- **Server**: pings every mux every 30 s (Cloudflare closes proxied WebSockets idle for about 100 s; background tabs throttle the client's own 25 s ping), the client answers; counter `mux_server_pings`.

What to do as a user: nothing. If the lock is Detectable, open the popover: the Reason says what is plain right now.

Test: `test/browser/resilience.mjs` (a Chrome with remote debugging, fake edge, TEST instance: offline 20 s, laptop sleep = offline plus every connection killed with `ss -K`, dropped mux, instance restart, three hard reloads; `--live` runs only the offline and hard reload phases, safe on the live port).

**Badge "Seal warning: server key changed"** (`SEAL_TOFU_MISMATCH`). The identity key differs from the one this browser pinned and no signed rotation leads to it. Either the state directory was lost or replaced (keys regenerated), or someone in the path serves another key. Check `fingerprint` on the server against the pin (DevTools, Application, IndexedDB `dsh-seal`, `kv/idfp`). If the server key really changed on purpose, clear the site data of dsh.example.com in that browser. Never rotate by deleting `identity.pem`: use `dsh-seal rotate-identity` (signed chain), then `systemctl reload dsh-seal`.

**Page loads, then stays blank on the very first visit.** The bootstrap page waits for the worker (up to 8 s) and reloads. If it loops: check that `/_s/sw.js` answers 200 with `Service-Worker-Allowed: /` and that cookies are allowed (`sealboot`).

**Chat does not stream / sockets reconnect.** `__dshSeal.muxState` should be `open` (`waiting` = offline, `connecting` = backing off); `mux_live` in health counts live mux sockets. A mux silent for 90 s is dropped (clients ping every 25 s, the server every 30 s). Inner socket refusals show as `SEAL_UPSTREAM_REFUSED` with the upstream status.

**`SEAL_UNKNOWN_SESSION` in the logs after a restart.** Expected: sessions live in memory; clients re-handshake transparently.

**`SEAL_INJECT_SKIPPED`.** The shell came with an encoding the standard library cannot decode (dsh-seal asks for gzip only, so this means an upstream change) or above 16 MiB. The shell passes through unchanged (plain).

**A user who is not in `identities` reports problems.** Their traffic is pure pass-through. Compare `curl -H 'X-Auth-Email: <their email>'` via 3082 and 3081 on loopback.

**dsh-seal does not start (`SEAL_LISTEN`).** Something else holds 127.0.0.1:3082 (the test instance: `systemctl --user stop dsh-seal-test`).

## Real-browser verification (loopback only)

```
systemd-run --user --unit dsh-seal-test -p MemoryMax=128M bin/dsh-seal -config deploy/test-offer.conf
systemd-run --user --unit dsh-seal-fakeedge -p MemoryMax=128M bin/fakeedge -listen 127.0.0.1:3083 -upstream 127.0.0.1:3082 -log /var/tmp/seal-work/edge.log
DSH_TOKEN=$(...launch token, never printed...) node test/browser/real-dsh.mjs --turn
```

`fakeedge` stands in for the reverse proxy plus the auth gateway (it sets `X-Auth-Email` on every request, like forwardAuth) and logs every request line, which is what an observer would see. The script uses a Chrome with remote debugging on 127.0.0.1:9222, opens one tab, clears only the test origin's worker, caches and IndexedDB, and closes its tab at the end or on its deadline. The first navigation needs `/?token=` because the dsh cookie name depends on the host and port. `--turn` sends "Reply with exactly: OK" to the scratch chat only.

## Sealed egress

- **An image, font or script from another site does not load**: open the lock popover. "Blocked" names the host and the reason (see ERRORS.md, "Sealed egress"). `journalctl -u dsh-seal | grep 'egress refused'` shows host and code (never the path). Per minute summaries: `journalctl -u dsh-seal | grep 'msg=egress '`.
- **Turn egress off at once** (kill switch): `egress=off` in `deploy/dsh-seal.conf`, then `sudo systemctl reload dsh-seal`. Open pages switch to direct on their next cross-origin request (the server answers `SEAL_EGRESS_OFF`, the worker remembers it), new pages get a worker with egress off. The indicator then shows those hosts as Escaped (Detectable): that is the honest state without egress.
- **A site needs a port other than 443**: `egress_ports=8443` (comma list). Never add LAN hosts: private ranges are refused by the Go guard and by the unit's `IPAddressDeny` both.
- **Block a tracker or a host**: `egress_deny_hosts=example-tracker.com` (suffix match).
- **WebRTC needed** (dsh-phone Direct mode): `egress_webrtc=allow` (reload; pages pick it up on their next load). It connects to the provider directly from the browser, outside the seal.
- **Test instance with egress** (never on the live port): build to `/var/tmp/seal-work/`, run it on 3087 with its own `state_dir`, fake edges per identity on fresh loopback hosts (a host that pinned another instance's key shows "Broken": use a new 127.0.0.x), then `node test/browser/egress.mjs http://127.0.0.x:PORT OUTDIR EDGELOG TAG --full [--turn]`. It records whether any request reached the network for another host (`Network.requestWillBeSentExtraInfo`) and fails if one did. `test/browser/killswitch.mjs` checks egress=off by SIGHUP with a page open. Stale DSH cookies of an earlier run on the same host stop dsh-proxy's token redirect: the harness clears the host's cookies first.
- **Careful with builds**: `scripts/build.sh` writes `bin/dsh-seal`, the binary the live unit runs. Keep `bin/dsh-seal.prev`; for tests build elsewhere and run `SEAL_BIN=/path test/e2e.sh`.
