# dsh-seal

An application layer encrypted channel for DeepSeek Harness (DSH) web traffic. The page encrypts locally and talks only to the DSH host; the host decrypts and talks to everyone else. A middle box between the browser and your server (a workplace TLS-inspecting proxy, a CDN that terminates TLS) sees one encrypted stream to your DSH host name: no URL paths, no query strings, no API bodies, no chat text.

dsh-seal is not a DSH plugin package: it is a small Go service that sits in front of DSH as a reverse proxy, plus a browser client (service worker and boot script) that it injects into the DSH page itself. DSH core and the plugins need no change.

Wire format: [docs/PROTOCOL.md](docs/PROTOCOL.md). Errors: [docs/ERRORS.md](docs/ERRORS.md). Operations: [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## How it sits in front of DSH

```
browser (boot.js + sw.js) -> CDN or TLS proxy (optional) -> reverse proxy + auth gateway -> dsh-seal 127.0.0.1:3082 -> upstream 127.0.0.1:3081 -> dsh web 127.0.0.1:3080
```

The upstream is DSH itself (`dsh web --host 127.0.0.1 --port 3080 --trusted-host dsh.example.com`) or whatever proxy you already run in front of it. The reverse proxy (traefik, Caddy, nginx) points the DSH host at dsh-seal instead of the upstream, after your login gateway has authenticated the user and set an identity header (`X-Auth-Email` by default, as forwardAuth gateways do).

- **dsh-seal** (Go, standard library only, static binary, about 15 MB RSS) is a reverse proxy. Everything that is not `/_s/*` passes through byte for byte (streaming bodies, event streams, chunked and 50 MB uploads, WebSocket upgrades as a raw tunnel); headers are preserved and only `X-Forwarded-For` is added when absent. In `passthrough` mode it is indistinguishable from a direct connection to the upstream.
- Sealed requests are decrypted and **replayed to the upstream on loopback** with the identity and routing headers of the outer request (which passed your reverse proxy and auth gateway), so per-user routing, the DSH launch token cookie and plugin routes behave exactly as without the seal.
- **Client** (TypeScript, esbuild, no runtime dependencies): `boot.js` is injected as the first element of `<head>` of the shell. It makes sure the service worker controls the page, then patches `WebSocket` and `EventSource` onto one sealed mux socket (`/_s/ws`). `sw.js` seals every other same-origin request (fetch, XHR, assets, iframes, navigations other than the shell) through `/_s/x`, streaming responses frame by frame.
- **Keys, fully automatic**: an ECDSA P-256 identity key and an ECDH P-256 key exchange key (rotated weekly, signed by the identity) live in `state_dir` (0600). Each page load makes a fresh ECDH key, the server proves it holds its key (HMAC confirmation), and every stream direction gets its own AES-256-GCM key from HKDF. The browser pins the identity fingerprint (silent TOFU); a changed identity without a signed rotation chain is refused with a warning badge.
- **Modes** (`deploy/dsh-seal.conf`, reload with SIGHUP): `passthrough` (pure proxy, installed workers retire), `offer` (seal when possible, plain still works, open lock on fallback), `require` (plain API requests of sealed identities refused; see "Require mode").
- **Resilience**: a hard reload ends sealed (bootstrap page from the server, stop and normal reload in boot.js, worker claim); the mux reconnects with backoff and jitter and waits while offline, frozen or asleep; worker fetches retry idempotent requests after a fresh handshake and fail others visibly; offer mode falls back to plain only after 25 s of failures with the network demonstrably up (`/_s/p`). Details: docs/TROUBLESHOOTING.md.
- **Status indicator**: a pixel lock in the last row of the DSH sidebar footer. Closed green lock "Encrypted" = sealed; open grey lock "Detectable" = something is plain right now (reason in the tooltip; the popover keeps the history); broken red lock "Broken" = server key changed. Keyboard reachable, with a popover showing state, session age, sealed requests, fallbacks, the short server key fingerprint and the mode. It lives in a shadow root and follows the light or dark theme. Code `client/src/indicator.ts`.
- **Who is sealed**: the identities in `identities=` (or `*`). Any other identity passes through untouched, byte for byte; sealed inner requests carry the same outer identity, so per-user routing still works.

## Threat model

Protected against an observer or a TLS-intercepting proxy between the browser and the server (including a CDN that terminates TLS):

- Contents of every API call, plugin route, event stream and WebSocket message (chat, mail, call signalling, files, settings), in both directions.
- URL paths and **query strings** of everything after the shell.
- Replay and tampering of sealed traffic: AEAD per frame with implicit sequence numbers, stream ids accepted once per session, sessions bound to the handshake transcript and to the authenticated identity, sessions held in memory only and gone after a restart, idle TTL 12 h.
- After the first visit, a swapped server key (a middle box offering its own key): the pinned fingerprint does not match and the page refuses to seal and shows a warning.

Honest limits:

- **First visit trust.** The page code and the server public key come over the same channel they protect. A proxy able to rewrite pages could serve modified code or its own key on the very first visit, or strip the injection entirely. Only a browser extension or a pinned native client closes this; neither is part of this project.
- **A rewriting proxy can always serve different code**, also later: the TOFU pin defends against a key swap with the real code, not against replaced code. Treat a "Seal warning" badge as an incident.
- **Visible to the observer**: the host name, the login gateway's cookie exchange and login pages, the first HTML shell, `boot.js` and `sw.js` (no personal data), the `sealboot` marker cookie, cookie values the server sets (copied to outer responses so the browser keeps them), and traffic **volume and timing** (a call is a steady stream; a long answer is a long stream). There is no padding.
- **Client authentication stays with your login gateway.** A proxy that captures the gateway's session cookie can replay it and run its own seal client: the seal makes traffic unreadable, it does not replace login. `require` mode only stops plain requests.
- **What still escapes with egress on** (see "Sealed egress"): top-level navigations the user starts (a click on a link to another site), the browser's own traffic (updates, safe browsing, sync, extensions), WebSockets opened inside Web Workers (their fetches are sealed by the service worker, their WebSocket constructor is not patched), and a connection hint or iframe inserted as raw HTML by a script after load (removed within the same task, but the browser may already have started it; the indicator then lists it as Escaped). Peer connections (WebRTC) cannot be proxied and are blocked instead. With `egress=off` every cross-origin request goes direct again and is listed as Escaped.
- **Remote sites see your server's IP address** for every egress request, a generic browser User-Agent and no cookies: sites that need the user's own login cookie (an embedded third-party app) do not work through egress; their content is blocked (iframes) or fetched logged out.
- **Non-browser clients** (curl, scripts on loopback) are unaffected and unprotected.

## Build, test, run

Requirements: Go 1.26 or newer, Node 22 or newer (client build and the interop tests).

```
scripts/build.sh                       # client (tsc + esbuild) and static binaries in bin/
go test -race -p 2 ./...               # Go unit and integration tests
test/e2e.sh                            # mock DSH behind dsh-seal, Node WebCrypto interop suite (incl. resilience)
go test -run XXX -fuzz FuzzSealedEnvelope -fuzztime 60s ./internal/server/
bin/sealbench -n 200 -path /manifest.webmanifest       # overhead against a running upstream
```

The built client is committed in `client/dist` and embedded into the binary, so `go build ./cmd/dsh-seal` alone also works.

## Deploy

1. `cp deploy/dsh-seal.conf.example deploy/dsh-seal.conf` and set `upstream`, `state_dir`, `identities`, `exclude_prefixes` (paths your reverse proxy routes to other services on the same host) and `egress_deny_cidrs` (your server's own public addresses). `deploy/dsh-seal.conf` and `deploy/backup/` are ignored by git: they are your live files.
2. `scripts/build.sh`, then check the config and print the key fingerprint: `bin/dsh-seal -config deploy/dsh-seal.conf fingerprint`.
3. Install `deploy/dsh-seal.service` (adjust `User`, paths and the `IPAddressDeny` list) and `deploy/dsh-seal-fallback.service`, then `systemctl enable --now dsh-seal`. Start in `mode=passthrough`.
4. Point the reverse proxy at `127.0.0.1:3082`. With the traefik file provider, `scripts/seal-switch.sh` does it safely: it switches one service's url and verifies within 10 s that the GUI answers through dsh-seal exactly as through the upstream, reverting on any failure.

```
export SEAL_TRAEFIK_FILE=/etc/traefik/dynamic/dsh.yml SEAL_TRAEFIK_SERVICE=dsh-backend SEAL_HOST=dsh.example.com
scripts/seal-switch.sh on passthrough   # reverse proxy -> 3082, verified within 10 s, auto-revert on failure
scripts/seal-switch.sh mode offer       # seal the identities in the config
scripts/seal-switch.sh status
scripts/seal-switch.sh off              # rollback: passthrough first, then the reverse proxy -> 3081
```

- **Add a user**: append the identity to `identities=` and `systemctl reload dsh-seal` (SIGHUP, no restart, sessions kept). Their next page load gets the bootstrap page once, then the sealed GUI.
- **Rollback**: `scripts/seal-switch.sh off` (passthrough first so the service workers retire, then the reverse proxy back to the upstream). Never stop the unit while the reverse proxy still points at 3082 (that is a 502 for everyone): always `off` first. If dsh-seal keeps failing, `dsh-seal-fallback.service` (OnFailure) runs `seal-switch.sh off` by itself. Browsers recover either way (`SEAL_ABSENT` retires the worker).
- **Upgrading**: keep the running binary as `bin/dsh-seal.prev` before `scripts/build.sh` overwrites `bin/dsh-seal`, then restart the unit (sessions are in memory; pages re-handshake transparently).

## Sealed egress

Every connection the DSH page (and its same-origin iframes) makes to **another host** travels sealed to dsh-seal, which fetches it from the internet itself and returns it sealed. An observer sees only your DSH host; the remote site sees your server, never the user's device or IP.

| Connection of the page | Path |
|---|---|
| fetch/XHR, img, script, style, font, CSS `url()`, `@import`, media with Range (206), manifests, preload/prefetch, workers' fetches | the service worker answers every cross-origin fetch event: sealed `/_s/x` with an absolute URL, the server fetches, the worker builds the Response (status, Content-Type, Range/206, cache headers; scripts, fonts, SRI and media work). Long-lived answers (`public, max-age >= 1 h`) stay in the worker cache |
| WebSocket and EventSource to other hosts | the sealed mux (`/_s/ws`); the server dials `wss://` (ws:// is upgraded) |
| `navigator.sendBeacon` | becomes a fetch, so it goes through the worker |
| same-origin documents the worker serves (iframes, report tabs) | the worker injects `boot.js?f=1` (frame mode: sockets, shim and counters, no indicator) and removes connection hints to other hosts before the parser sees them |

What is blocked (counted as "blocked", not as an escape):

- `<link rel=preconnect|dns-prefetch|prerender>` to other hosts: they open connections without a fetch event. Removed from the shell (server side), from documents the worker serves, from Link headers, and the `rel` setter and `setAttribute` are patched so scripts cannot add them; `x-dns-prefetch-control: off` is set.
- Cross-origin `<iframe>`/`<frame>` (for example YouTube): replaced by a placeholder with an "Open in a new tab" link (a sealed full-page proxy of other sites is not safe: scripts of the remote site would run on your origin). `object`/`embed` to other hosts are dropped, `a[ping]` to other hosts stripped.
- `RTCPeerConnection`, `webkitRTCPeerConnection`, `WebTransport`: their traffic cannot be proxied. The constructors throw `NotAllowedError` with a console note. `egress_webrtc=allow` lifts this for everyone.
- A server refusal (private address, deny list, rate limit, CORS refused by the remote) is a network error in the page, as the browser itself would give.

Server side (`internal/server/egress.go`, standard library): only for a live sealed session of an identity in `egress_identities`; https only (http and ws upgraded, never sent in plaintext); DNS resolved in the dialer, every address checked (loopback, RFC 1918, CGNAT, link-local incl. cloud metadata, ULA, multicast, documentation and benchmark ranges, 6to4/Teredo/NAT64, v4-mapped, the server's own addresses from `egress_deny_cidrs`) and the **checked address is dialled** (DNS rebinding cannot swap in a private one); every redirect hop re-checked, at most 5; ports 443 (and 80 rewritten to 443) plus `egress_ports`; local names (`localhost`, `.local`, `.internal`, `.lan`, `.home.arpa`, ...) and `egress_deny_hosts` refused; 50 MB per response (streamed), 16 MB per request body, timeouts (connect 10 s, TLS 10 s, headers 30 s, body idle 120 s, total 15 min); per identity 30 requests/s (burst 300), 48 in flight, 32 sockets. Nothing of the outer request is forwarded (no gateway or DSH cookies, no X-Auth-*, no X-Forwarded-*); the server sends a generic Chrome User-Agent, `Referer` = the target's own origin, `Origin` = the page origin only where a browser would. Remote `Set-Cookie`, `Link`, `Alt-Svc`, HSTS, `Report-To`/NEL and `Clear-Site-Data` are dropped. The example unit additionally denies private ranges at the kernel (`IPAddressDeny`), so a guard bug still cannot reach the LAN.

Logs: one summary line per minute per (identity hash, host): requests, bytes, status classes; refusals with host and code. Never paths, queries or bodies. Counters on `/_s/health`: `egress`, `egress_bytes`, `egress_refused`, `egress_fail`, `egress_sockets`.

Config keys: `egress=on|off` (kill switch), `egress_identities` (default `*`), `egress_deny_hosts` (suffixes), `egress_deny_cidrs`, `egress_ports`, `egress_max_bytes`, `egress_max_request`, `egress_rate`, `egress_burst`, `egress_parallel`, `egress_sockets`, `egress_header_timeout`, `egress_webrtc=block|allow`. Test only: `egress_unsafe_allow_nets`, `egress_ca_file` (the e2e TLS mock).

## Require mode (prepared, not recommended yet)

What `require` breaks, and what to do first:

| Breaks | Why | Before enabling |
|---|---|---|
| A browser view the worker cannot control: a private window without service workers, a browser with service workers disabled | every API call goes out plain and is refused (`SEAL_PLAIN_REFUSED`) | accept it, or keep such users in offer mode |
| First visit straight to a non shell page (a deep link, with no worker installed yet) | only `shell_paths` get the bootstrap page | add those paths to `shell_paths` and test |
| Non browser clients through the reverse proxy (curl, scripts with a gateway cookie) | they cannot seal | exempt their paths with `plain_paths` |
| Silent fallbacks in offer mode | the server cannot see a client's plain fallback | watch the lock for a while in offer mode first |

Enable per identity only after testing on a separate instance (`deploy/test-offer.conf` style, its own port and `state_dir`).

## Layout

```
cmd/dsh-seal        service and CLI (fingerprint, bundle-json, rotate-identity)
cmd/mockupstream    DSH look-alike for the e2e harness
cmd/sealbench       latency and throughput against a running upstream
internal/sealcrypto key schedule, frame cipher, replay window (+ frozen vectors)
internal/keystore   identity, rotation chain, key exchange keys, bundle verification
internal/server     proxy, injection, handshake, sealed fetch, mux, egress (egress.go, hints.go), config, metrics
internal/wsproto    minimal RFC 6455 (server and client)
internal/sealclient Go client (tests, benchmarks)
client/src          boot.ts, sw.ts, seal.ts, fetch.ts, mux.ts, shim.ts (egress page shim), hints.ts, indicator.ts (compiled into client/dist, embedded)
test/               e2e harness, Node interop suite, real-browser harness (Chrome over CDP), fakeedge
deploy/             dsh-seal.service, dsh-seal-fallback.service, dsh-seal.conf.example, test-offer.conf
scripts/            build.sh, seal-switch.sh
```

Why a hand-written WebSocket: the standard library has none, the mux needs only binary messages without extensions, and 300 lines are easier to audit than a dependency. `httputil.ReverseProxy` already streams correctly (FlushInterval -1) and tunnels upgrades, so it carries the pass-through path.

## License

MIT, see [LICENSE](LICENSE).

---

Built by Luca Tzekos, who also makes [**Job Opportunities API**](https://jobopportunitiesapi.org): employer-direct job data with per-field provenance you can verify yourself, free to read and available as an API. If this project is useful to you, a star on this repo or a look at [jobopportunitiesapi.org](https://jobopportunitiesapi.org) is the best thanks.
