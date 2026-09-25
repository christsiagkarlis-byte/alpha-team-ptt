# Deployment Guide — Team Stadium Hardened Runtime

## Scope

Team Stadium runs as a Node.js and Socket.IO service with PostgreSQL and Redis. The application must be placed behind a TLS reverse proxy because GPS, WebAuthn, browser media, and secure Socket.IO use require the public application origin to be HTTPS/WSS.

This guide uses the hardened Compose configuration in this repository. PostgreSQL and Redis remain private. The application is bound to `127.0.0.1` by default, so the reverse proxy is the only public entry point.

## Prepare configuration and secret files

Copy `.env.example` to `.env`. The `.env` file contains only non-secret configuration and the five paths to secret files. Create the secret directory outside the repository when possible. If it must be local to the deployment checkout, it is already excluded by `.gitignore` and `.dockerignore`.

```bash
install -d -m 0700 secrets
umask 077
printf '%s' 'a-long-random-postgres-password' > secrets/postgres_password
printf '%s' 'a-long-random-redis-password' > secrets/redis_password
printf '%s' 'at-least-32-random-characters-for-jwt-signing' > secrets/jwt_secret
printf '%s' 'a-long-random-administrator-api-key' > secrets/admin_api_key
printf '%s' 'a-private-team-access-code-or-bcrypt-hash' > secrets/access_code
chmod 0600 secrets/*
```

Set the following public-origin values in `.env` before starting the service.

```env
CORS_ORIGIN=https://stadium.example.com
WEBAUTHN_RP_ID=stadium.example.com
WEBAUTHN_ORIGIN=https://stadium.example.com
TRUST_PROXY=true
BIND_ADDRESS=127.0.0.1
```

The public origin must be the exact HTTPS origin seen by browsers. Do not use a trailing slash in `WEBAUTHN_ORIGIN`. Production startup rejects an insecure WebAuthn origin or a localhost RP ID.

## Build and start

The images are digest-pinned and the Node image uses `npm ci --omit=dev --ignore-scripts`. Build and start the stack after secret files and `.env` are complete.

```bash
npm ci
npm test
docker compose --env-file .env up --build -d
```

The first initialization of the persistent PostgreSQL volume applies `database.sql`. Existing volumes do not rerun initialization scripts. For an existing deployment, take and verify a database backup before applying the updated schema manually.

```bash
pg_dump "$DATABASE_URL" > pre-hardening-backup.sql
docker compose exec -T alpha-db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" < database.sql
```

Do not run `docker compose down -v` in production because that removes database and Redis volumes.

## Reverse proxy requirements

The reverse proxy must terminate TLS, redirect HTTP to HTTPS, forward `X-Forwarded-For` and `X-Forwarded-Proto`, and support WebSocket upgrade requests for `/socket.io/`. It must proxy to `http://127.0.0.1:${PORT}` rather than publishing the application directly to the Internet. Restrict the public listener to the expected hostname.

After the proxy is active, verify the public health endpoint and WebSocket transport from the final HTTPS hostname.

```bash
curl -fsS https://stadium.example.com/health
```

A healthy response has this shape.

```json
{"status":"ok","database":"ok","redis":"ok","websocket":"ok"}
```

## Retention, pagination, and storage controls

The server starts a bounded retention pass and a storage monitor. Defaults are documented in `.env.example`. Review them before production use because operational retention requirements differ by organization. The retention pass processes at most `RETENTION_BATCH_SIZE` rows per affected table. It can also be triggered by an administrator for a controlled maintenance run.

```bash
curl -fsS -X POST https://stadium.example.com/api/admin/maintenance/retention \
  -H "x-admin-api-key: $(cat /secure/path/admin_api_key)"
```

Storage information is available to an authenticated administrator.

```bash
curl -fsS https://stadium.example.com/api/admin/storage \
  -H "x-admin-api-key: $(cat /secure/path/admin_api_key)"
```

The response includes PostgreSQL bytes, the largest PostgreSQL tables, Redis memory, Redis key count, and warning names when the configurable threshold is exceeded. Administrative endpoints have a default quota of twenty requests per minute per source IP.

Incident, notification, and tracking-history endpoints now return an opaque `next_cursor` when another page is available. Clients should pass that value as `cursor` in the next request and should not construct or modify it.

## Session and Socket.IO operations

Every HTTP session request and every Socket.IO event checks the current user state in PostgreSQL. ALFA member reset and device revoke increment the user’s session version, clear device-bound material, release PTT locks, and disconnect the user’s active sockets. A client receives `session_revoked` and must authenticate or enroll again.

Server-side Socket.IO enforcement applies default quotas for connection attempts, location updates, incident reports, PTT starts, PTT joins, PTT stops, and WebRTC signaling. A location update is accepted no more frequently than every five seconds by default. Tune these values in `.env` only after load testing the expected client population.

## Validation before release

Run the standard regression checks and the integration suite from a host with PostgreSQL server binaries, Redis, OpenSSL, and Node.js available.

```bash
npm test
npm run test:integration
```

The integration runner creates temporary PostgreSQL and Redis instances, starts the application, tests the WebAuthn option path through local HTTPS, validates reset-driven session invalidation, checks database retention and storage monitoring, and opens twelve concurrent Socket.IO clients. It cleans the temporary services after completion.

## Routine security procedures

Rotate the access code, JWT signing secret, Redis password, database password, and administrative API key after any suspected exposure. Replace each secret file atomically, restart the affected containers, and invalidate active device sessions when the JWT secret changes. Keep the values distinct; do not reuse the access code as the JWT secret or administrator key.

Pin updates are deliberate. When updating Node, PostgreSQL, or Redis base images, change the tag and digest together, rebuild, run `npm test` and `npm run test:integration`, then deploy through the normal change-control process.
