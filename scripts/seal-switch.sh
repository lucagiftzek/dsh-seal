#!/usr/bin/env bash
# seal-switch.sh: put dsh-seal into (or take it out of) the live path of
# your DSH host (traefik file provider), safely.
#
#   seal-switch.sh status
#   seal-switch.sh on [passthrough|offer|require]   default passthrough
#   seal-switch.sh mode passthrough|offer|require    change mode only (reload)
#   seal-switch.sh off [--stop]                      traefik back to 3081
#
# "on" sets the mode, starts dsh-seal.service, points the traefik service $SEAL_TRAEFIK_SERVICE at
# 127.0.0.1:3082 (traefik hot-reloads the file) and verifies within 10 s, through
# traefik on loopback, that requests now flow through dsh-seal and that the GUI
# shell answers exactly as dsh-proxy does. Any failure reverts traefik to 3081.
# "off" first switches dsh-seal to passthrough (installed service workers see
# SEAL_DISABLED and retire themselves), then points traefik back to 3081.
set -uo pipefail

# Everything site specific comes from the environment (a traefik file provider
# setup is assumed: one service whose loadBalancer url is switched).
REPO=$(cd "$(dirname "$0")/.." && pwd)
CONF=${SEAL_CONF:-$REPO/deploy/dsh-seal.conf}
BIN=${SEAL_BIN:-$REPO/bin/dsh-seal}
TRAEFIK_FILE=${SEAL_TRAEFIK_FILE:?set SEAL_TRAEFIK_FILE to the traefik dynamic file that routes your DSH host}
SVC=${SEAL_TRAEFIK_SERVICE:-dsh-backend}
BACKUP_DIR=$REPO/deploy/backup
OLD_URL=${SEAL_UPSTREAM_URL:-http://127.0.0.1:3081}
NEW_URL=${SEAL_URL:-http://127.0.0.1:3082}
EDGE=${SEAL_EDGE:-http://127.0.0.1:8080}
HOST=${SEAL_HOST:?set SEAL_HOST to the public host name of your DSH, e.g. dsh.example.com}
CHECK_EMAIL=${SEAL_CHECK_EMAIL:-alice@example.com}
SEAL=$NEW_URL
PROXY=$OLD_URL
UNIT=${SEAL_UNIT:-dsh-seal.service}

say() { printf '%s\n' "$*"; }
die() { say "SEAL_SWITCH_FAILED: $*"; exit 1; }

backend_url() {
  awk -v svc="$SVC" '$0 ~ "^    " svc ":"{f=1;next} f&&/url:/{gsub(/.*url: *"|".*/,"");print;exit} f&&/^    [a-z]/{exit}' "$TRAEFIK_FILE"
}

# Rewrite the url of the DSH backend service only, in place (same inode, so
# traefik's watcher sees a write, not a new file).
set_backend() {
  local from=$1 to=$2 tmp
  tmp=$(mktemp "${TMPDIR:-/var/tmp}/traefik.yml.XXXXXX")
  awk -v svc="$SVC" -v from="$from" -v to="$to" '
    $0 ~ "^    " svc ":" {f=1}
    f && /^    [a-z]/ && $0 !~ "^    " svc ":" {f=0}
    f && index($0, "url: \"" from "\"") {sub(from, to); f=0}
    {print}' "$TRAEFIK_FILE" > "$tmp" || { rm -f "$tmp"; return 1; }
  if ! grep -q "url: \"$to\"" "$tmp"; then rm -f "$tmp"; return 1; fi
  if [ "$(diff "$TRAEFIK_FILE" "$tmp" | grep -c '^[<>]')" -ne 2 ]; then
    say "refusing: the edit would change more than one line"; rm -f "$tmp"; return 1
  fi
  sudo sh -c "cat '$tmp' > '$TRAEFIK_FILE'" || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
}

counter() { curl -s -m 3 "$SEAL/_s/health" | sed -n 's/.*"passthrough":\([0-9]*\).*/\1/p'; }
health_mode() { curl -s -m 3 "$SEAL/_s/health" | sed -n 's/.*"mode":"\([a-z]*\)".*/\1/p'; }

set_mode() {
  local m=$1
  case "$m" in passthrough|offer|require) ;; *) die "mode must be passthrough, offer or require";; esac
  sed -i "s/^mode=.*/mode=$m/" "$CONF"
  "$BIN" -config "$CONF" check >/dev/null || die "config check failed"
  if systemctl is-active -q "$UNIT"; then
    sudo systemctl reload "$UNIT" || die "reload failed"
  else
    sudo systemctl start "$UNIT" || die "dsh-seal.service did not start"
  fi
  for _ in $(seq 20); do [ "$(health_mode)" = "$m" ] && return 0; sleep 0.25; done
  die "dsh-seal does not report mode $m on $SEAL/_s/health"
}

status() {
  say "traefik $SVC: $(backend_url)"
  say "dsh-seal.service:   $(systemctl is-active $UNIT) ($(systemctl is-enabled $UNIT 2>/dev/null))"
  local h; h=$(curl -s -m 3 "$SEAL/_s/health")
  if [ -n "$h" ]; then say "dsh-seal health:    $h"; else say "dsh-seal health:    not answering on $SEAL"; fi
}

# Verify that traefik now sends the DSH backend traffic through dsh-seal.
verify_on() {
  local before after code_edge s_seal s_proxy deadline=$((SECONDS + 10))
  before=$(counter); [ -n "$before" ] || { say "health endpoint silent"; return 1; }
  while [ $SECONDS -lt $deadline ]; do
    code_edge=$(curl -s -o /dev/null -m 3 -w '%{http_code}' -H "Host: $HOST" "$EDGE/favicon.svg")
    after=$(counter)
    if [ "$code_edge" = 200 ] && [ -n "$after" ] && [ "$after" -gt "$before" ]; then
      # GUI shell: the same request must get the same answer via dsh-seal and dsh-proxy
      s_seal=$(curl -s -o /dev/null -m 5 -w '%{http_code}' -H "Host: $HOST" -H "X-Auth-Email: $CHECK_EMAIL" "$SEAL/")
      s_proxy=$(curl -s -o /dev/null -m 5 -w '%{http_code}' -H "Host: $HOST" -H "X-Auth-Email: $CHECK_EMAIL" "$PROXY/")
      if [ "$s_seal" = "$s_proxy" ] && [ "${s_seal:0:1}" != 5 ]; then
        say "verified: traefik -> dsh-seal (favicon 200, request counter $before -> $after), shell $s_seal = dsh-proxy $s_proxy"
        return 0
      fi
      say "shell mismatch: dsh-seal $s_seal, dsh-proxy $s_proxy"; return 1
    fi
    sleep 0.5
  done
  say "traefik did not route through dsh-seal within 10 s (edge $code_edge, counter $before -> ${after:-?})"
  return 1
}

# sourcing the script (tests) defines the functions only
[ "${BASH_SOURCE[0]}" = "$0" ] || return 0
cmd=${1:-status}
case "$cmd" in
  status) status ;;
  mode) set_mode "${2:-}"; status ;;
  on)
    m=${2:-passthrough}
    [ -x "$BIN" ] || die "$BIN missing: run scripts/build.sh"
    [ "$(backend_url)" = "$OLD_URL" ] || { [ "$(backend_url)" = "$NEW_URL" ] && { say "already on"; set_mode "$m"; status; exit 0; }; die "unexpected $SVC url $(backend_url)"; }
    curl -s -o /dev/null -m 3 "$PROXY/favicon.svg" || die "dsh-proxy is not answering on 3081; not switching"
    set_mode "$m"
    mkdir -p "$BACKUP_DIR"
    cp -p "$TRAEFIK_FILE" "$BACKUP_DIR/llm.yml.$(date +%Y%m%d-%H%M%S)"
    trap 'say "interrupted: reverting"; set_backend "$NEW_URL" "$OLD_URL"; exit 1' INT TERM
    set_backend "$OLD_URL" "$NEW_URL" || die "could not edit $TRAEFIK_FILE (nothing changed)"
    if verify_on; then
      trap - INT TERM
      say "ON: $HOST now flows through dsh-seal in mode $m. Rollback: $0 off"
    else
      set_backend "$NEW_URL" "$OLD_URL" && say "reverted traefik to $OLD_URL" || say "REVERT FAILED: set the $SVC url in $TRAEFIK_FILE back to $OLD_URL by hand"
      die "verification failed, traffic is back on dsh-proxy"
    fi
    ;;
  off)
    if [ "$(backend_url)" = "$NEW_URL" ]; then
      # let installed service workers retire themselves first
      systemctl is-active -q "$UNIT" && set_mode passthrough
      set_backend "$NEW_URL" "$OLD_URL" || die "could not edit $TRAEFIK_FILE"
      for _ in $(seq 20); do
        [ "$(curl -s -o /dev/null -m 3 -w '%{http_code}' -H "Host: $HOST" "$EDGE/favicon.svg")" = 200 ] && break; sleep 0.5
      done
      say "OFF: traefik $SVC -> $OLD_URL"
    else
      say "already off ($SVC -> $(backend_url))"
    fi
    [ "${2:-}" = "--stop" ] && sudo systemctl stop "$UNIT" && say "dsh-seal.service stopped"
    status
    ;;
  *) say "usage: $0 status | on [passthrough|offer|require] | mode <m> | off [--stop]"; exit 2 ;;
esac
