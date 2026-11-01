# dsh-seal wire protocol, version 1

This document is normative. The Go server (`internal/sealcrypto`, `internal/server`) and the TypeScript client (`client/src`) implement exactly this; the frozen vectors in `internal/sealcrypto/vectors.go` are checked by both the Go tests and the Node interop suite.

Notation: `||` concatenation, `u32`/`u64` big endian unsigned integers, `b64u` unpadded base64url, `"..."` ASCII bytes. `LABEL = "dsh-seal/1"`.

## 1. Primitives

| Use | Primitive (WebCrypto name) |
|---|---|
| Server identity | ECDSA P-256, SHA-256, signatures in IEEE P1363 form (r \|\| s, 64 bytes) |
| Key exchange | ECDH P-256, public keys raw uncompressed (65 bytes), shared secret = x coordinate (32 bytes) |
| Derivation | HKDF-SHA256 (an empty salt equals 32 zero bytes) |
| Confirmation | HMAC-SHA256 |
| Frames | AES-256-GCM, 96 bit nonce, 128 bit tag |

## 2. Server keys and the bundle

- **Identity key** `ID` (ECDSA P-256), long-term, `identity.pem` (PKCS#8, mode 0600). `fp(ID) = b64u(SHA-256(LABEL || " id" || 0x00 || ID_raw))`.
- **Key exchange key** `KX` (ECDH P-256), rotated every `kx_rotate` (default 7 days), valid for two periods (`kx.json`, 0600). `kid = b64u(SHA-256(KX_raw)[0:8])`. Certificate signature: `sig_ID(LABEL || " kx" || 0x00 || KX_raw || u64(nbf) || u64(exp))`.
- **Identity rotation** (`dsh-seal rotate-identity`): the old identity signs `LABEL || " rot" || 0x00 || OLD_raw || NEW_raw || u64(t)`. The last 8 links travel in the bundle.

Every page load receives the bundle inside `/_s/boot.js` and `/_s/sw.js` as `self.__DSH_SEAL_CFG = {"bundle": B, "cfg": C}`:

```json
{"v":1,"id":"<b64u ID_raw>","fp":"<fp>","chain":[{"prev":"..","next":"..","t":0,"sig":".."}],
 "kx":{"kid":"..","pub":"<b64u KX_raw>","nbf":0,"exp":0,"sig":".."}}
```

`C = {mode, shell[], exclude[], sealedOnly, version}`.

### Client verification (silent TOFU)

1. `fp(id) == fp` and the KX certificate verifies under `id`; `now <= exp + 1 day`.
2. Pinned fingerprint `P` (IndexedDB `dsh-seal/kv/idfp`): none, or `P == fp`: accept, pin `fp`.
3. Otherwise walk `chain` from `P`: each link must start at the current fingerprint and verify under that key; reaching `fp` accepts and re-pins. Anything else: `SEAL_TOFU_MISMATCH`, the client does not seal and shows the warning badge.

## 3. Handshake: `POST /_s/h`

Request (JSON): `{"v":1,"kid":"<kid>","cpub":"<b64u C_raw>"}` where `C` is a fresh ECDH P-256 key generated per page load (non-extractable private key).

Server: `shared = ECDH(KX_priv, C)`, random `sid` (16 bytes) and `sn` (32 bytes), then

```
th = SHA-256(LABEL || " hs" || 0x00 || ID_raw || KX_raw || C_raw || sid || sn)
ms = HKDF(ikm = shared, salt = th, info = LABEL || " ms", 32)
cf = HMAC(HKDF(ikm = ms, salt = "", info = LABEL || " cf", 32), th)
```

Response: `{"v":1,"sid":"..","sn":"..","cf":"..","ttl":<s>}`. The client recomputes and verifies `cf` (proof that the server holds `KX_priv`), then keeps `ms` as a non-extractable HKDF key. The server stores `{sid, ms, outer identity}` in memory only; a restart forgets every session (clients re-handshake on `SEAL_UNKNOWN_SESSION`). Sessions expire after `session_ttl` idle or twice that in total.

The session is **bound to the outer identity** (the `X-Auth-Email` the reverse proxy and its auth gateway set on the handshake): any later use with another identity is `SEAL_IDENTITY_MISMATCH`.

## 4. Streams and frames

Every sealed exchange is a **stream** with a client-chosen id `s` (u64, starting at 1, never reused). The server accepts each id once, out of order within a window of 4096 below the highest id seen (`SEAL_REPLAY` otherwise).

Keys: `K(dir, s, e) = HKDF(ikm = ms, salt = "", info = LABEL || " k" || dir || u64(s) || u32(e), 32)` with `dir` = `'c'` (client to server) or `'s'`, and epoch `e = floor(seq / 2^16)` (a new key every 65536 frames).

Frame `seq` (0, 1, 2, ... per direction and stream, implicit, never on the wire):

```
nonce     = 0x00000000 || u64(seq)
aad       = LABEL || sid || dir || u64(s) || u64(seq)
plaintext = type (1 byte) || payload (<= 65536 bytes)
frame     = AES-256-GCM(K(dir, s, e), nonce, plaintext, aad)
```

A dropped, duplicated, reordered, truncated or cross-stream frame fails authentication.

## 5. Sealed fetch: `POST /_s/x`

Body: `"DSX1" || sid || u64(s)` then length-prefixed frames `u32(len) || frame`, direction `c`:

| type | payload |
|---|---|
| `0x01` HEAD | JSON `{"m":method,"u":"/path?query","h":[[name,value],...],"n":bodyLength,"md":fetchMode,"dt":destination}` |
| `0x02` DATA | body bytes (any number of frames) |
| `0x03` END | empty; required before the server replays a body-less request |

The full URL including the query lives only inside HEAD. The server rebuilds the request for the upstream: page headers minus protected ones (Host, Cookie, Content-Length, Origin, Accept-Encoding, hop-by-hop, `X-Auth-*`, `X-Forwarded-*`, `X-Real-Ip`, `Forwarded`, `Cf-*`, `Sec-Fetch-*`, `Sec-WebSocket-*`, `Proxy-*`, `Remote-*`, `X-Seal-*`), plus identity and routing headers copied from the **outer** request (Cookie, `X-Auth-*`, `X-Forwarded-*`, `X-Real-Ip`, `Forwarded`, `Cf-*`; User-Agent and Accept-Language when the page set none; Origin for non-GET methods; `Sec-Fetch-Site` from outside, `Sec-Fetch-Mode/Dest` from `md/dt`). `Accept-Encoding: gzip` is requested.

Response: outer `200 application/octet-stream`, `Cache-Control: no-store`, then frames, direction `s`:

| type | payload |
|---|---|
| `0x01` HEAD | JSON `{"s":status,"h":[[name,value],...],"z":"gzip"?}`; with `z` the body is still gzip and Content-Encoding/Length are removed from `h` |
| `0x02` DATA | body bytes as they arrive (flushed per frame: event streams stay live) |
| `0x03` END | clean end |
| `0x04` ERROR | JSON `{"code":"SEAL_UPSTREAM_BROKEN",...}`: the upstream body broke |

`Set-Cookie` of the inner response is also copied to the outer response (the browser cookie jar only reads real headers). Outer errors before any frame are JSON `{"code","message"}` with header `X-Seal-Error: <code>`; all of them happen before the inner request is replayed, so the client may safely retry or fall back.

## 6. Sealed WebSocket mux: `GET /_s/ws`

A real WebSocket. First binary message: `"DSW1" || sid || u64(s)`. Every following message is one sealed frame (no length prefix) on stream `s`; plaintext payload = `u32(channel) || data`. Close codes on the outer socket: 4400 bad envelope or frame, 4401 unknown session, 4403 identity mismatch.

| type | dir | data |
|---|---|---|
| `0x10` OPEN | c | JSON `{"k":"ws"\|"http","u":"/path?q","p":[protocols],"h":[[n,v]],"md","dt"}` |
| `0x11` OPENED | s | ws: `{"p":protocol,"x":""}`; http: `{"s":status,"h":[[n,v]]}` |
| `0x12` TEXT, `0x13` BINARY | both | message bytes; `| 0x80` = more fragments follow (fragments of at most 65532 bytes) |
| `0x14` CLOSE | both | `u16(code) || reason`; for http the end of the body |
| `0x15` ERROR | s | JSON `{"code","message","status"}`; the channel is gone |
| `0x16` CREDIT | both | `u32(bytes)` returned to the sender's window |
| `0x17` PING / `0x18` PONG | both | channel 0, 8 bytes; the client pings every 25 s, the server pings every 30 s (0.5.0; a client answers PONG, older clients ignore it), the server drops a mux silent for 90 s |

Flow control: each direction of each channel starts with a 4 MiB window; DATA consumes it, CREDIT refills it (the server credits after writing to the upstream socket, the client credits as soon as it receives). Up to 512 channels per mux. `http` channels are GET only and carry EventSource streams.

## 7. Modes and the client

- `passthrough`: no injection, `/_s/*` answers `SEAL_DISABLED` (404) except `/_s/sw.js`, which serves a worker that unregisters itself (the kill switch reaches installed workers).
- `offer`: shell responses (`shell_paths`, GET, 200, text/html) of sealed identities get `<script src="/_s/boot.js?v=..">` as the first element of `<head>`. A browser without the `sealboot` cookie gets a bootstrap page (boot.js only) instead, so no DSH code is loaded before the worker is in control. Plain requests still work.
- `require`: as offer, and plain requests of sealed identities are refused (`SEAL_PLAIN_REFUSED`, 403) except the shell navigation, `/_s/*`, `plain_paths` and `exclude_prefixes`. Clients get `sealedOnly` and never fall back.

boot.js patches `window.WebSocket` and `window.EventSource` (same-origin, not excluded) onto the mux; sw.js seals every other same-origin request, navigations included, except `/_s/*`, the shell navigation and `exclude_prefixes`. Long-lived responses marked `public, max-age >= 3600` are kept in the worker's Cache Storage, because responses built by a worker never enter the HTTP cache.

## 8. Sealed egress (0.4.0)

No new endpoint and no new frame type.

- `/_s/x` HEAD `u` may be an **absolute** `http(s)://` URL: the server fetches it from the internet (egress) instead of replaying it to the upstream. HEAD may carry `"rd"`: the page's redirect mode (`follow` default, `error`, `manual`; with `error`/`manual` the server returns the 3xx unfollowed). The response HEAD carries `"u"`: the final URL after redirects. Page headers are filtered (no Cookie, Origin, Referer, User-Agent, Accept-Language, `Sec-*`, identity or proxy headers); nothing of the outer request is copied.
- Refusals are inner responses: status 4xx/5xx with `X-Seal-Egress-Error: <code>` (see ERRORS.md); the outer response is the usual `200 application/octet-stream`.
- Mux OPEN `u` may be an absolute `ws(s)://` URL (kind `ws`, the server dials `wss://`) or `http(s)://` URL (kind `http`, an EventSource GET). Refusals are `0x15 ERROR` frames with the egress code.
- Client config `C` gains `egress` (bool, per identity) and `webrtc` (`block` or `allow`).
- `boot.js?f=1` is frame mode: the worker injects it (with `<meta http-equiv="x-dns-prefetch-control" content="off">`) after `<head>` of every same-origin HTML document it serves (navigations other than the shell). The shell gets the same meta tag from the server, and connecting hints (`preconnect`, `dns-prefetch`, `prerender`) to other hosts are removed from the shell, from those documents and from `Link` headers.

## 9. Resilience (0.5.0)

No new frame type; additions only.

- `GET /_s/p`: network probe, `204`, `Cache-Control: no-store`, empty, answered in every mode and for anyone. Clients use it to tell "the network is down" (no answer) from "the sealed path fails" (an answer). Offer mode falls back to plain only after the sealed path kept failing for 25 s while the probe answers.
- Server PING on the mux every 30 s (keeps the Cloudflare idle timer of about 100 s from closing a quiet socket when the browser throttles the page's timers).
- Hard reload: a shell `GET` with the `sealboot` cookie and `Pragma: no-cache` or `Cache-Control: no-cache` gets the bootstrap page, unless it carries the cookie `sealhr` (set by boot.js for 30 s right before the normal reload it does itself). `sealhr` and `sealboot` never reach the upstream.
- Worker message `{t: "dsh-seal-claim"}`: the worker calls `clients.claim()` (it also does on every activate).
- Sessions are not bound to a mux socket: after a drop (sleep, network change) a new mux uses the same `sid` with a new stream id, no handshake; 4401 means the server forgot the session (restart, or `session_ttl` idle) and the client handshakes again.
