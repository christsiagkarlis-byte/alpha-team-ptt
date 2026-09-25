# Team Stadium — Security and Operations Hardening Report

**Prepared by:** Manus AI  
**Date:** 24 September 2026

## Result

The requested security hardening work is complete. The server now enforces administrative quotas, shared session revocation, Socket.IO connection and event quotas, event-frequency limits, canonical geographic validation, bounded retention, cursor pagination, and storage monitoring. The Compose deployment no longer carries runtime secrets as ordinary environment values. It uses file-mounted secrets, a loopback-only application bind, immutable base-image digests, a non-root read-only application container, and a production-only dependency install.

The implementation was validated with unit-style regression checks and a disposable PostgreSQL 16 plus Redis 7 integration environment. That integration suite also exercised a local HTTPS reverse proxy for WebAuthn option generation and a twelve-client Socket.IO load scenario. All tests passed.

## Implemented controls

| Area | Implemented control | Operational effect |
|---|---|---|
| Administrative access | A dedicated `adminLimiter` protects dashboard, activation, kill-switch, alert, retention, and storage endpoints. | Administrative API keys cannot be used for unlimited rapid requests from one source address. |
| HTTP and Socket.IO sessions | Both transports call the same `resolveDeviceSession` function. It verifies signature, issuer, audience, token type, active account state, hardware binding, and `session_version`. | A token revoked in PostgreSQL is rejected consistently by REST endpoints and Socket.IO packets. |
| Member reset and revocation | Reset increments `session_version`, clears credentials, passkeys, push subscriptions, active tracking state, current location, pending activation tokens, Redis WebAuthn challenges, PTT locks, and live sockets. | A reset immediately makes an old device unusable and removes its residual session material. |
| Socket.IO abuse control | Connection, per-event quota, and minimum-frequency checks run server-side. Policies cover location, incidents, PTT, and WebRTC signaling. | A modified or malicious client cannot bypass the browser’s location throttle or flood common realtime events. |
| Geospatial data | HTTP and Socket.IO locations use one latitude, longitude, accuracy, speed, heading, and radius validation model. PostgreSQL constraints mirror those ranges. | Invalid coordinates and impossible values are rejected before persistence and also cannot be inserted accidentally through a normal database path. |
| Data lifecycle | Bounded periodic cleanup deletes expired operational data in batches. Cursor pagination limits incident, notification, and route-history payloads. | Tables and API responses remain bounded rather than growing without limit. |
| Storage visibility | An authenticated administrative storage endpoint records PostgreSQL size, largest tables, Redis memory, key count, and configurable threshold warnings. | Operators can detect capacity pressure before it becomes an outage. |
| Client rendering | Dynamic `innerHTML`, `outerHTML`, `insertAdjacentHTML`, and `document.write` paths were removed from `public/app.js`. | API error text and realtime values are inserted as text nodes rather than interpreted as markup. |
| WebAuthn | Production startup rejects a non-HTTPS origin or localhost RP ID. Registration now supplies a binary WebAuthn user identifier, which the current SimpleWebAuthn server requires. | Passkey configuration is tied to the intended HTTPS origin and avoids the previous registration-options runtime error. |
| Container runtime | Docker Compose uses secret files, constrained service access, a private internal network, immutable image digests, `npm ci`, a non-root process, dropped Linux capabilities, a read-only application filesystem, a small temporary filesystem, memory and PID limits, and a loopback bind. | The deployment has a smaller secret-exposure and container-runtime attack surface. |

## Session and realtime enforcement

A session token is no longer accepted merely because its JSON Web Token signature is valid. Each HTTP request and every Socket.IO packet is checked against the current PostgreSQL user row. The check compares the user ID, username, hardware UUID, active flag, and `session_version`. Packet middleware runs before each named realtime event, so revocation between the handshake and a later PTT, GPS, incident, or signaling action is detected. The socket receives a `session_revoked` notification, releases any Redis PTT lock, and disconnects.

The ALFA reset endpoint and the ALFA device-revoke endpoint both increment `session_version` inside their transaction. They then remove credential material and disconnect every matching socket. This repairs the previous gap in which a reset could remove a member’s device binding while a socket remained connected with an already-authorized in-memory user object.

The Socket.IO policy includes a per-source connection quota, a per-user quota window, and a minimum interval for high-frequency events. The defaults permit one location update every five seconds and no more than twenty-four location events per minute. PTT starts, incident reports, joins, stops, and WebRTC SDP/ICE signaling have separate quotas. The server emits `rate_limited` with a retry interval when a client exceeds a policy.

## Geographic integrity and data lifecycle

The same validator processes a location from a Socket.IO update, an incident, a wellbeing check-in, a checkpoint scan, a checkpoint creation request, and a geofence request. Latitude is limited to −90 through 90, longitude to −180 through 180, accuracy to 100 km, motion speed to 150 m/s, heading to 0 through 360 degrees, checkpoints to 10 km, and geofences to 100 km. The database adds equivalent checks for persisted locations, radii, movement, and paired coordinate columns.

Retention runs during startup and at an interval selected by `RETENTION_INTERVAL_SECONDS`. Every pass deletes at most `RETENTION_BATCH_SIZE` rows per table. Defaults retain route history for thirty days, notifications and wellbeing records for ninety days, legacy incident events for 180 days, audit and security incident records for one year, activation material for seven days, and stale push subscriptions for 180 days. These are operational defaults rather than legal retention advice. They must be reviewed against the organization’s own incident, employment, and privacy obligations before production deployment.

Incident, notification, and tracking-history endpoints implement keyset pagination. A cursor carries an opaque row identifier and a microsecond-precise timestamp. This avoids large `OFFSET` scans and prevents duplicates or omissions when multiple rows share a millisecond-level JavaScript timestamp.

## Deployment configuration

The revised Compose file expects paths to five local secret files: PostgreSQL password, Redis password, JWT signing secret, administrative API key, and access code. Compose mounts each value under `/run/secrets`; the application supports the matching `*_FILE` convention. Docker documents this model as a per-service secret mount and notes that it avoids passing sensitive values through ordinary environment variables.[1]

The Dockerfile is pinned to a concrete Node 22.13.0 Alpine image digest and uses `npm ci --omit=dev --ignore-scripts`. `npm ci` requires a lockfile, does not rewrite it, and fails when the lockfile and manifest disagree, so it is suitable for a reproducible build path.[2] The PostgreSQL and Redis Compose images are also digest-pinned. These pins must be deliberately updated after a vulnerability review rather than silently floating to a new image.

Production must terminate TLS at a reverse proxy that forwards WebSocket upgrades and sets the trusted proxy headers expected by the application. `CORS_ORIGIN`, `WEBAUTHN_ORIGIN`, and `WEBAUTHN_RP_ID` must name the public HTTPS site. SimpleWebAuthn uses the RP ID and expected origin when generating and verifying WebAuthn ceremonies; its documentation permits localhost only for local development.[3]

## Validation evidence

| Validation | Command | Result |
|---|---|---|
| JavaScript syntax | `node --check server.js && node --check public/app.js` | Passed. |
| Client DOM regression checks | `npm test` | Five tests passed. The suite verifies that unsafe dynamic HTML sinks are absent, that session and rate-limit controls are present, and that database and Compose controls are represented. |
| PostgreSQL and Redis integration | `npm run test:integration` | Passed with a temporary PostgreSQL 16 cluster and Redis 7 server. |
| HTTPS WebAuthn path | Included in `npm run test:integration` | Passed through a local TLS proxy. The test received registration options from the session-protected endpoint. |
| Session reset propagation | Included in `npm run test:integration` | Passed. A member reset invalidated the old HTTP token and caused the live Socket.IO connection to receive `session_revoked`. |
| Pagination, retention, storage, and administrative quotas | Included in `npm run test:integration` | Passed. The suite verified pagination continuation, batched audit retention, storage telemetry, and a `429` quota response. |
| Database geographic constraints | Included in `npm run test:integration` | Passed. A direct PostgreSQL insert with `speed_mps = 151` was rejected by `location_history_speed_check`, independently of the application validator. |
| Limited Socket.IO load | Included in `npm run test:integration` | Passed with twelve concurrent authenticated sockets. All joins succeeded, and a too-fast second GPS event received a frequency-limit notification. |

## Remaining production prerequisites

The included integration suite is intentionally local and uses a self-signed test certificate. Before a public release, the reverse proxy must use a publicly trusted certificate, strict HTTPS redirects, WebSocket upgrade forwarding, and a configuration that permits only the intended origin. The production secret files must be created with restrictive filesystem permissions and must remain outside the repository.

The implementation records storage pressure to standard output and exposes it to an authenticated administrator. Production operations should forward those logs to the existing monitoring system and set alerting around `postgres_database_threshold_exceeded` and `redis_memory_threshold_exceeded`. The retention defaults should also be approved by the data owner before the first scheduled cleanup cycle.

The sandbox used for validation does not include a Docker CLI. Compose YAML structure and the production dependency installation path were validated locally, but the final deployment environment should additionally run `docker compose build` and `docker compose up` under its normal release process.

No browser-only deployment can claim native Android Play Integrity or Apple App Attest. The implemented WebAuthn user verification improves device-bound authentication within the web model, but native platform attestation remains outside the scope of this web application.

## References

[1]: https://docs.docker.com/compose/how-tos/use-secrets/ "Manage secrets securely in Docker Compose"
[2]: https://docs.npmjs.com/cli/v9/commands/npm-ci/ "npm ci command documentation"
[3]: https://simplewebauthn.dev/docs/packages/server "SimpleWebAuthn server documentation"
