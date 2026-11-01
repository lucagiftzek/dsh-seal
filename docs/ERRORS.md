# SEAL_* error codes

Stable codes. They appear in JSON error bodies (`{"code","message"}`), in the `X-Seal-Error` response header, in mux close reasons and ERROR frames, in client exceptions (`SealError.code`), in `window.__dshSeal.reason` and in the service log. Messages never contain keys, tokens or request contents.

## Server, outer HTTP errors (before anything is replayed upstream)

| Code | Status | Meaning | What to do |
|---|---|---|---|
| `SEAL_DISABLED` | 404 | dsh-seal is in passthrough mode | Expected after a kill switch; workers retire themselves |
| `SEAL_NOT_ELIGIBLE` | 403 | the identity is not in `identities` | Add it to `identities` if it should be sealed |
| `SEAL_NOT_FOUND` | 404 | unknown `/_s/` endpoint | Client and server versions differ; reload |
| `SEAL_METHOD` | 405 | wrong method for a seal endpoint | Client bug |
| `SEAL_HS_BAD_REQUEST` | 400 | handshake JSON malformed | Client bug |
| `SEAL_HS_UNKNOWN_KEY` | 409 | key exchange key expired or unknown | The page is older than two rotation periods; the client re-handshakes, a reload fixes it |
| `SEAL_HS_BAD_KEY` | 400 | client public key invalid | Client bug or tampering |
| `SEAL_UNKNOWN_SESSION` | 401 | session unknown or expired (dsh-seal restarted) | Client handshakes again automatically |
| `SEAL_IDENTITY_MISMATCH` | 403 | session used with another `X-Auth-Email` | Possible cookie theft or a login switch; the client re-handshakes on reload |
| `SEAL_REPLAY` | 403 | stream id reused or older than the window | Replay attempt, or a client counter bug |
| `SEAL_BAD_ENVELOPE` | 400 | wrong magic, short prefix, bad frame length, missing END | Client bug or tampering |
| `SEAL_FRAME_AUTH` | 400 | a frame failed AES-GCM authentication | Tampering, or client and server disagree on keys |
| `SEAL_BAD_REQUEST` | 400 | inner request invalid (path not starting with `/`, targets `/_s/`, bad method, body length mismatch) | Client bug or tampering |
| `SEAL_PLAIN_REFUSED` | 403 | require mode: a plain request from a sealed identity | Expected for stale tabs; reload |

## Server, inside the sealed stream

| Code | Where | Meaning |
|---|---|---|
| `SEAL_UPSTREAM_DOWN` | sealed 502 response, mux ERROR, plain 502 | dsh-proxy (127.0.0.1:3081) not reachable |
| `SEAL_UPSTREAM_BROKEN` | ERROR frame | upstream body ended early |
| `SEAL_UPSTREAM_REFUSED` | mux ERROR (with `status`) | the upstream refused an inner WebSocket upgrade |
| `SEAL_MUX_PROTOCOL` | mux ERROR or close 4400 | channel id reused, too many channels, unknown frame |

## Client only

| Code | Meaning |
|---|---|
| `SEAL_TOFU_MISMATCH` | the server identity differs from the pinned one without a signed rotation: not sealed, warning badge |
| `SEAL_BUNDLE_INVALID`, `SEAL_BUNDLE_EXPIRED` | bundle signature, fingerprint or key validity failed |
| `SEAL_HS_CONFIRM` | the server could not prove the session key |
| `SEAL_TRUNCATED` | a response stream ended inside a frame or without END |
| `SEAL_FRAME_EMPTY`, `SEAL_FRAME_TOO_LARGE` | malformed frame |
| `SEAL_NETWORK` | the outer request failed (or the handshake fetch did). Idempotent requests are retried after a fresh handshake (backoff, waiting while offline, up to 35 s); others fail visibly (popover "Failed", never replayed, never plain). Plain fallback only after 25 s of failures with the network up (offer) |
| `SEAL_ABSENT` | `/_s/x` answered 404 without `X-Seal-Error`: traefik no longer routes through dsh-seal; the worker unregisters itself |
| `SEAL_MUX_CONNECT`, `SEAL_MUX_ERROR` | the mux socket could not be opened for 25 s with the network up (offline and sleep only wait), or a channel failed |
| `SEAL_HTTP_<status>` | any other outer status |

## Service and tooling

| Code | Meaning |
|---|---|
| `SEAL_CONFIG` | invalid config key or value (the reload keeps the old config) |
| `SEAL_KEYS_DIR`, `SEAL_KEYS_READ`, `SEAL_KEYS_WRITE` | state directory or key files unusable |
| `SEAL_LISTEN` | cannot bind the listen address (another instance on 3082?) |
| `SEAL_INJECT_SKIPPED` | a shell response could not be injected (unsupported Content-Encoding or over 16 MiB); it passed through unchanged |
| `SEAL_SWITCH_FAILED` | `seal-switch.sh` stopped; traffic is on dsh-proxy (3081) |

## Sealed egress (inside the envelope)

Egress refusals are sealed inner responses (the observer cannot tell them from any answer): status as listed, header `X-Seal-Egress-Error: <code>`, a one line text body. The worker turns them into a network error in the page and lists the host under "Blocked" in the indicator. On the mux they arrive as an ERROR frame with the same code. The service logs `egress refused` with the host and the code, never the path.

| Code | Status | Meaning | What to do |
|---|---|---|---|
| `SEAL_EGRESS_OFF` | 403 | `egress=off`, or the identity is not in `egress_identities` | Kill switch on purpose; the worker goes direct at once (listed as Escaped) |
| `SEAL_EGRESS_BAD_URL` | 400 | malformed URL, credentials in the URL, bad redirect | Page bug |
| `SEAL_EGRESS_SCHEME` | 400 | not http(s) (fetch) or ws(s) (socket), also after a redirect | Expected (ftp, file, data) |
| `SEAL_EGRESS_PORT` | 403 | port not 443 (80 is rewritten to 443) and not in `egress_ports` | Add the port to `egress_ports` if it is a legitimate public service |
| `SEAL_EGRESS_DENIED` | 403 | local name (`localhost`, `.local`, `.internal`, `.lan`, `.home.arpa`, ...) or `egress_deny_hosts` | On purpose |
| `SEAL_EGRESS_DNS` | 502 | the name did not resolve | Remote problem |
| `SEAL_EGRESS_FORBIDDEN` | 403 | every address of the name is private, loopback, link-local (metadata), CGNAT, ULA, multicast, reserved or the server's own (also after a redirect or a rebinding answer) | SSRF guard working; never relax it for a LAN host |
| `SEAL_EGRESS_CONNECT` | 502 | TCP connect failed | Remote problem |
| `SEAL_EGRESS_TLS` | 502 | TLS handshake or certificate failed (the server never falls back to plaintext) | Remote problem |
| `SEAL_EGRESS_TIMEOUT` | 504 | connect, TLS, headers (30 s), body idle (120 s) or total (15 min) | Remote slow |
| `SEAL_EGRESS_REDIRECTS` | 502 | more than 5 redirects | Remote loop |
| `SEAL_EGRESS_TOO_LARGE` | 413 / ERROR frame | request body over `egress_max_request` (16 MB), or response over `egress_max_bytes` (50 MB; the stream ends with this ERROR frame) | Raise the cap if a legitimate asset needs it |
| `SEAL_EGRESS_RATE` | 429 | over `egress_rate`/`egress_burst`, 30 s queued for `egress_parallel`, or `egress_sockets` reached | Look at the per minute `egress` log lines for the identity hash |
| `SEAL_EGRESS_REFUSED` | remote status | the remote refused the WebSocket upgrade | Remote decision |
| `SEAL_EGRESS_FAILED` | 502 | anything else on the way to the remote | Check the journal |

Client side reasons in the indicator (not server codes): `CORS refused by the remote` (a cors mode fetch whose answer has no matching `Access-Control-Allow-Origin`, as the browser itself would refuse), `redirect refused` (the page asked `redirect: "error"`), `iframe`, `connection hint removed`, `RTCPeerConnection blocked`, `egress off`, `no sealed session (...)`.
