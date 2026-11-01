# Changelog

## 0.5.0 (2026-11-02)

First public release (squashed history).

- Resilience: a hard reload ends sealed (bootstrap page on a hard reload, stop and normal reload in boot.js, worker claim); mux reconnect with backoff and jitter, offline and sleep aware; worker retries idempotent requests and fails others visibly; offer mode falls back to plain only after a grace window with the network up; the lock shows the current state with history; server ping and probe.
- Bootstrap page without a favicon request; real-browser resilience harness.
- Public tree: example config `deploy/dsh-seal.conf.example` (the live config is ignored by git), generic example units, `seal-switch.sh` configured through `SEAL_*` environment variables, neutral identities and addresses in tests, no default identities or exclude prefixes in the built-in config.

## 0.4.0

- Sealed egress: the server fetches other hosts for the page (SSRF guarded, caps, rate limits); the worker and a page shim route every cross-origin connection through the seal; cross-origin iframes get a placeholder; WebRTC blocked unless allowed; kill switch `egress=off` takes effect at once (`SEAL_EGRESS_OFF`).

## 0.3.0

- Always visible status indicator in the DSH sidebar footer (Encrypted, Detectable, Broken) with a details popover.
- Offer mode, systemd unit with an OnFailure fallback, `seal-switch.sh`.

## 0.2.0

- Bootstrap page for first visits, `SEAL_ABSENT` self-retire, Node WebCrypto interop suite, e2e harness, mock upstream, fuzzing, sealbench.

## 0.1.0

- Go service (pass-through, injection, key schedule, sealed fetch, mux), TypeScript client, Go tests.
