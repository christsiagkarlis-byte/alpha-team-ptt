#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
RUNTIME="$ROOT/.test-runtime"
PG_PORT="${TEST_PG_PORT:-55432}"
REDIS_PORT="${TEST_REDIS_PORT:-56379}"
APP_PORT="${TEST_APP_PORT:-3310}"
HTTPS_PORT="${TEST_HTTPS_PORT:-3443}"
PG_DATA="$RUNTIME/postgres"
PG_SOCKET="$RUNTIME/pgsocket"
PG_LOG="$RUNTIME/postgres.log"
REDIS_LOG="$RUNTIME/redis.log"
APP_LOG="$RUNTIME/app.log"
TLS_KEY="$RUNTIME/localhost-key.pem"
TLS_CERT="$RUNTIME/localhost-cert.pem"
PG_BIN="$(pg_config --bindir 2>/dev/null || true)"

cleanup() {
  local status=$?
  [[ -n "${APP_PID:-}" ]] && kill "$APP_PID" 2>/dev/null || true
  [[ -n "${REDIS_PID:-}" ]] && kill "$REDIS_PID" 2>/dev/null || true
  if [[ -d "$PG_DATA" ]]; then "$PG_BIN/pg_ctl" -D "$PG_DATA" -m fast stop >/dev/null 2>&1 || true; fi
  exit "$status"
}
trap cleanup EXIT

[[ -x "$PG_BIN/initdb" && -x "$PG_BIN/pg_ctl" ]] || { echo 'PostgreSQL server binaries are required.' >&2; exit 1; }
command -v redis-server >/dev/null || { echo 'redis-server is required.' >&2; exit 1; }
command -v openssl >/dev/null || { echo 'openssl is required.' >&2; exit 1; }

rm -rf "$RUNTIME"
mkdir -p "$RUNTIME" "$PG_SOCKET"
"$PG_BIN/initdb" -D "$PG_DATA" -A trust -U ubuntu --no-locale >/dev/null
printf "port = %s\nlisten_addresses = '127.0.0.1'\nunix_socket_directories = '%s'\n" "$PG_PORT" "$PG_SOCKET" >> "$PG_DATA/postgresql.conf"
"$PG_BIN/pg_ctl" -D "$PG_DATA" -l "$PG_LOG" -w start >/dev/null
"$PG_BIN/createdb" -h 127.0.0.1 -p "$PG_PORT" -U ubuntu team_stadium_test
"$PG_BIN/psql" -h 127.0.0.1 -p "$PG_PORT" -U ubuntu -d team_stadium_test -v ON_ERROR_STOP=1 -f "$ROOT/database.sql" >/dev/null

redis-server --bind 127.0.0.1 --port "$REDIS_PORT" --save '' --appendonly no --daemonize yes --pidfile "$RUNTIME/redis.pid" --logfile "$REDIS_LOG"
REDIS_PID=$(cat "$RUNTIME/redis.pid")
redis-cli -h 127.0.0.1 -p "$REDIS_PORT" ping | grep -qx PONG

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout "$TLS_KEY" -out "$TLS_CERT" -subj '/CN=localhost' >/dev/null 2>&1
export NODE_ENV=test
export PORT="$APP_PORT"
export DATABASE_URL="postgresql://ubuntu@127.0.0.1:${PG_PORT}/team_stadium_test"
export REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"
export JWT_SECRET='test-only-jwt-secret-minimum-length-1234567890'
export ADMIN_API_KEY='test-only-administrator-api-key-1234567890'
export ACCESS_CODE='test-access-code'
export CORS_ORIGIN="https://localhost:${HTTPS_PORT}"
export WEBAUTHN_ORIGIN="https://localhost:${HTTPS_PORT}"
export WEBAUTHN_RP_ID='localhost'
export ADMIN_RATE_LIMIT_MAX=3
export ADMIN_RATE_LIMIT_WINDOW_SECONDS=60
export SOCKET_CONNECTION_LIMIT=30
export SOCKET_EVENT_WINDOW_SECONDS=60
export SOCKET_LOCATION_MIN_INTERVAL_MS=5000
export TEST_APP_PORT="$APP_PORT"
export TEST_HTTPS_PORT="$HTTPS_PORT"
export TEST_TLS_KEY="$TLS_KEY"
export TEST_TLS_CERT="$TLS_CERT"
node "$ROOT/server.js" >"$APP_LOG" 2>&1 &
APP_PID=$!

for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${APP_PORT}/health" >/dev/null; then break; fi
  sleep 0.25
done
curl -fsS "http://127.0.0.1:${APP_PORT}/health" >/dev/null
node --test "$ROOT/test/integration.test.js"
