# NocaSIEM backend

Node.js/Express backend for the NocaSIEM dashboard: user accounts with
editable profiles, log source (IP/port) management with active
connectivity testing, real UDP + TCP log receivers, correlation-based
alerting, login brute-force protection, an audit log, and a WebSocket
feed for live updates.

## Setup

```bash
cd nocasiem-backend
npm install
cp .env.example .env
# open .env and set a real JWT_SECRET
npm start
```

You should see:
```
NocaSIEM API listening on http://localhost:4000
WebSocket live feed on ws://localhost:4000/ws
Syslog ingest listener bound on UDP port 5514
Syslog ingest listener bound on TCP port 5515
```

## How it works

- **One ingest port per protocol, many sources.** Real SIEMs (Splunk,
  Wazuh, etc.) run a small number of fixed collector ports that every
  device sends to. In the dashboard's Settings page, "port" is the port
  *you configure on the sending device* (its syslog/forwarder
  destination). Point UDP sources at `INGEST_PORT` (default `5514`) and
  TCP sources at `INGEST_TCP_PORT` (default `5515`). The IP you register
  per source is used to match incoming traffic and mark it "last seen" /
  active - matching is by IP only, since that's the only reliable
  identifier available once a packet arrives.
- **Alerts vs. logs.** Every incoming line is stored as a log. It's also
  run through `utils/rules.js` - a small keyword matcher - and promoted
  to an alert if it matches (e.g. "failed password" -> Brute force
  attempt, High).
- **Correlation / escalation.** `utils/rules.js` also tracks how many
  times the *same* rule fired from the *same* source IP in the last 2
  minutes. 5+ matches auto-escalates the alert to Critical with a
  "(Nx in 2 min - escalated)" label - this is the same basic logic real
  SIEMs use to turn "one failed login" into "this is an active
  brute-force attack." Tune `CORRELATION_WINDOW_MS` / `CORRELATION_THRESHOLD`
  in that file, or add your own rules.
- **Connectivity testing.** `POST /api/sources/:id/test` actively opens a
  TCP connection to the registered IP:port and reports whether it's
  reachable, with latency. UDP is connectionless, so that case returns
  `reachable: null` with an explanation instead of a misleading pass/fail.
- **Login protection.** `utils/loginAttempts.js` locks out an
  IP+email pair for 10 minutes after 5 failed login attempts, since this
  product's own login is as much a target as anything it monitors.
- **Audit log.** Register, login, profile updates, password changes, and
  source add/remove are all recorded and available via `GET /api/audit-log`.
- **Storage.** Everything is kept in `data.json` in this folder (no
  external database needed to get started). Swap `db.js` for a real
  database later - routes never touch the file directly.
- **Admin panel.** The first account ever registered automatically
  becomes an `admin`. Admins can list every user, promote/demote roles,
  suspend/reactivate accounts, delete accounts, and see an org-wide
  audit log - via `/api/admin/*`. **Passwords are never exposed**, not
  even to admins: they're one-way bcrypt hashes, so nobody can view or
  export a user's actual password. To reset a user's access, suspend
  their account or delete it - there's intentionally no "view/reset to
  known password" flow, since that would require storing passwords
  reversibly, which defeats the point of hashing them.

## Admin API reference

| Method | Path                        | Description                                  |
|--------|-----------------------------|-----------------------------------------------|
| GET    | /api/admin/users            | List all users (safe fields, no passwords)   |
| PATCH  | /api/admin/users/:id/role   | `{role: "admin"|"user"}`                     |
| PATCH  | /api/admin/users/:id/status | `{status: "active"|"suspended"}`             |
| DELETE | /api/admin/users/:id        | Delete an account and its sources            |
| GET    | /api/admin/audit-log        | Every user's activity (admin oversight)      |

All admin routes require the caller's own account to have `role: "admin"`
(403 otherwise). Built-in safety rails: you can't suspend, demote, or
delete yourself, and the last remaining admin can't be demoted or deleted
(so you can never lock yourself out entirely).

## API reference

| Method | Path                  | Auth | Description                              |
|--------|-----------------------|------|-------------------------------------------|
| POST   | /api/auth/register    | no   | Create an account                         |
| POST   | /api/auth/login       | no   | Get a JWT (rate-limited after 5 fails)    |
| GET    | /api/auth/me          | yes  | Current user                              |
| PATCH  | /api/auth/me          | yes  | Update `username`/`email`                 |
| PATCH  | /api/auth/password    | yes  | Change password `{currentPassword,newPassword}` |
| GET    | /api/sources          | yes  | List your log sources                     |
| POST   | /api/sources          | yes  | Add a source `{name, ip, port, protocol}` |
| DELETE | /api/sources/:id      | yes  | Remove a source                           |
| POST   | /api/sources/:id/test | yes  | Actively test IP:port reachability        |
| GET    | /api/stats            | yes  | KPI numbers for the dashboard             |
| GET    | /api/alerts           | yes  | Recent alerts                             |
| PATCH  | /api/alerts/:id       | yes  | Update alert status                       |
| GET    | /api/logs             | yes  | Recent raw log lines                      |
| GET    | /api/audit-log        | yes  | Recent account/security activity          |
| WS     | /ws                   | no   | Live push of new `log`/`alert` events     |

Authenticated requests need `Authorization: Bearer <token>`.

## Sending a test log

With the server running:

```bash
# UDP - Linux/macOS logger command
logger -n 127.0.0.1 -P 5514 -d "Failed password for admin from 10.0.0.7"

# UDP - netcat
echo "Port scan detected from 10.0.0.9" | nc -u -w0 127.0.0.1 5514

# TCP
echo "Unauthorized root access from 10.0.0.3" | nc 127.0.0.1 5515
```

Register the source first via `POST /api/sources` with the matching `ip`
so it shows up as active, then check `GET /api/alerts`.

To see correlation escalation, send the same rule-matching message 5+
times within 2 minutes from the same IP - the alert severity jumps to
Critical automatically.

## Connecting the dashboard frontend to this backend

Set the dashboard's API base URL (in Settings, in the dashboard UI) to
`http://localhost:4000`. If you're running the dashboard as a hosted
Claude artifact (served over HTTPS) rather than locally, most browsers
will block it from calling a plain `http://localhost` backend
(mixed-content policy). To avoid that, either:
- run the dashboard frontend locally too (e.g. `npm create vite`, paste
  the component in, `npm run dev`), or
- put a local HTTPS reverse proxy (e.g. `mkcert` + `caddy`) in front of
  this API, or
- tunnel it with `ngrok http 4000` and use the HTTPS URL it gives you.
