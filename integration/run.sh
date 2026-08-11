#!/usr/bin/env sh

set -eu

pebble_ref="${PEBBLE_REF:-v2.10.1}"
pebble_source="${PEBBLE_SOURCE:-}"
pebble_dir=""
pebble_pid=""
pebble_log=""
directory_url="https://127.0.0.1:14000/dir"
repo_root="$(CDPATH= cd "$(dirname "$0")/.." && pwd)"

cd "$repo_root"

cleanup() {
	if [ -n "$pebble_pid" ]; then
		kill "$pebble_pid" 2>/dev/null || true
		wait "$pebble_pid" 2>/dev/null || true
	fi
	if [ -n "$pebble_dir" ]; then
		rm -rf "$pebble_dir"
	fi
	if [ -n "$pebble_log" ]; then
		rm -f "$pebble_log"
	fi
}
trap cleanup EXIT INT TERM

if [ -z "$pebble_source" ]; then
	pebble_dir="$(mktemp -d "${TMPDIR:-/tmp}/certgot-pebble.XXXXXX")"
	git clone --depth 1 --branch "$pebble_ref" https://github.com/letsencrypt/pebble.git "$pebble_dir"
	pebble_source="$pebble_dir"
fi

pebble_bin="$pebble_source/pebble"
(cd "$pebble_source" && go build -o "$pebble_bin" ./cmd/pebble)
pebble_log="$(mktemp "${TMPDIR:-/tmp}/certgot-pebble.XXXXXX.log")"

(cd "$pebble_source" && \
	PEBBLE_VA_ALWAYS_VALID=1 \
	PEBBLE_VA_NOSLEEP=1 \
	PEBBLE_WFE_NONCEREJECT=0 \
	"$pebble_bin" -config test/config/pebble-config.json) >"$pebble_log" 2>&1 &
pebble_pid=$!

attempt=0
while ! curl --insecure --fail --silent "$directory_url" >/dev/null; do
	attempt=$((attempt + 1))
	if [ "$attempt" -ge 30 ]; then
		cat "$pebble_log" >&2
		exit 1
	fi
	sleep 1
done

CERTGOT_PEBBLE_DIRECTORY_URL="$directory_url" go test -count=1 -tags integration ./...
