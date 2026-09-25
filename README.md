# Team Stadium

Team Stadium is a closed Node.js, Express, PostgreSQL, Redis, Socket.IO, WebRTC, and WebAuthn application for secure team communications and security operations. It provides device enrollment, passkeys, session revocation, Push-to-Talk signaling, optional GPS sharing, SOS workflows, incident management, checkpoints, geofences, retention controls, and operational storage monitoring.

## Security posture

The application uses a shared server-side device-session resolver for HTTP and Socket.IO. A valid JSON Web Token is insufficient by itself: every request and realtime packet must also match the current PostgreSQL account state, device binding, and session version. ALFA reset, revoke, kill-switch, and logout actions invalidate the session version, clear relevant credential material, release PTT locks, and disconnect matching sockets.

Administrative routes have HTTP quotas. Socket.IO enforces source connection quotas, per-user event quotas, and server-side minimum intervals for GPS updates. Client-side throttles are therefore not a security boundary. Common validators protect all coordinate and radius inputs, and PostgreSQL repeats the key geographic and motion constraints.

The detailed implementation and test evidence are in [HARDENING_REPORT.md](HARDENING_REPORT.md). Deployment instructions are in [DEPLOYMENT.md](DEPLOYMENT.md).

## Local development

For a non-container development environment, set the required environment variables directly or through a local `.env` file. The required values are `DATABASE_URL`, `REDIS_URL`, `JWT_SECRET`, `ADMIN_API_KEY`, and `ACCESS_CODE`. `JWT_SECRET` must have at least 32 characters and `ADMIN_API_KEY` at least 24 characters.

```bash
npm ci
npm start
```

The Docker deployment does not use plain secret values in `.env`. It reads secrets from files mounted at `/run/secrets`. Copy `.env.example`, create the referenced secret files with mode `0600`, and set a final public HTTPS origin for `CORS_ORIGIN`, `WEBAUTHN_RP_ID`, and `WEBAUTHN_ORIGIN`.

```bash
cp .env.example .env
# Create the five secret files described in DEPLOYMENT.md.
docker compose --env-file .env up --build -d
```

The application container is intentionally bound to loopback by default. Put a TLS reverse proxy in front of it and forward Socket.IO WebSocket upgrades. PostgreSQL and Redis are internal-only services.

## Main endpoints

The health endpoint is `GET /health`. Administrative routes are protected with `x-admin-api-key`; `GET /api/admin/dashboard/status`, `GET /api/admin/storage`, and `POST /api/admin/maintenance/retention` are useful operations endpoints. Session-protected security routes accept a Bearer token or a JSON `session_token`.

List routes use bounded keyset pagination. `POST /api/security/incidents/list`, `POST /api/security/notifications`, and `POST /api/security/tracking/history` return `next_cursor` where another page exists. Treat cursors as opaque and send the returned value as `cursor` in the next request.

## Tests

```bash
npm test
npm run test:integration
```

The regression suite checks safe client rendering and required security controls. The integration runner creates temporary PostgreSQL and Redis instances, exercises HTTPS WebAuthn option generation, validates revocation across HTTP and Socket.IO, tests pagination, retention, storage monitoring, HTTP quotas, and opens twelve concurrent Socket.IO clients.

## Operational data lifecycle

The default retention schedule is configured in `.env.example`. Location history is retained for thirty days by default. Notifications and wellbeing records are retained for ninety days. Audit and security incident records are retained for one year. Review and change these values before production use to match the organization’s approved retention policy.
