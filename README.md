# NocaSIEM

A self-hosted security dashboard: user accounts, log source management,
real UDP/TCP syslog ingestion, rule-based alerting with correlation, an
admin panel, and a live-updating React dashboard. It's one project, run by
one Node.js server.

```
server/          Express API, WebSocket live feed, syslog listeners
  server.js      entry point - also serves the dashboard
  db.js          JSON-file data store
  ingest.js      UDP/TCP syslog receivers
  routes/        /api/auth, /api/sources, /api/admin, /api/stats...
  middleware/    auth + admin checks
  utils/         detection rules, login lockout
src/             React dashboard
index.html       dashboard entry page
public/          static assets
.env             your settings (copy from .env.example)
data.json        accounts, sources, logs and alerts (created automatically)
```

## Run it

Requires Node.js 20.19 or newer.

```bash
npm install
```

Copy `.env.example` to `.env` and set `JWT_SECRET` (see the table below), then:

```bash
npm run dev
```

Open http://localhost:4000. The first account you register becomes the admin.

`npm run dev` starts everything in one process: the API, the live feed, the
syslog listeners, and the dashboard with hot reload. Editing files in `src/`
updates the browser instantly; editing files in `server/` restarts the server.

**Production:**

```bash
npm run build
```

```bash
npm start
```

`build` compiles the dashboard into `dist/`; `start` serves it together with
the API. `start` refuses to run with a missing or weak `JWT_SECRET`.

**Send a test log** (register a source with IP `127.0.0.1` first; lines from
unregistered IPs are dropped):

```bash
echo "Failed password for root from 10.0.0.7" | nc -u -w0 127.0.0.1 5514
```

| Port (default) | What                                                   |
|----------------|--------------------------------------------------------|
| `PORT` 4000    | Website + `/api/*` + `/ws` (put HTTPS in front of this) |
| UDP 5514       | Syslog ingest (`INGEST_PORT`)                          |
| TCP 5515       | Syslog ingest (`INGEST_TCP_PORT`)                      |

## Configuration

Set these in `.env` locally, or as environment variables on your host.

| Variable             | Required | Notes |
|----------------------|----------|-------|
| `JWT_SECRET`         | yes      | 32+ random characters. Generate: `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`. Changing it signs everyone out. |
| `ALLOW_REGISTRATION` | recommended | Set to `false` after creating your admin account so strangers can't sign up. |
| `ADMIN_EMAIL`        | recommended for new deploys | Only this email can create the first (admin) account on an empty instance. |
| `INGEST_ALLOW_UNREGISTERED` | no | Default `false`: log lines from IPs not registered as a source are dropped. |
| `INGEST_RATE_LIMIT`  | no       | Max log lines per second per source IP (default 100). |
| `HOST`               | no       | Listen address. `npm run dev` defaults to `127.0.0.1`; `npm start` to all interfaces. |
| `DATA_FILE`          | recommended in production | Path on a **persistent** disk, e.g. `/data/nocasiem.json`. Defaults to `data.json` in the project folder. |
| `TRUST_PROXY`        | behind a proxy | `1` when behind Nginx/Caddy/a PaaS load balancer, so login lockouts use real client IPs. |
| `PORT`               | no       | Most hosts set this automatically. |
| `INGEST_PORT`, `INGEST_TCP_PORT` | no | Syslog listener ports. |
| `CORS_ORIGIN`        | no       | Only if you host the dashboard on a different domain. |

## Deploying

Build command: `npm install && npm run build` · Start command: `npm start`

(If your host installs with `NODE_ENV=production`, use
`npm install --include=dev && npm run build` so Vite is available for the build.)

- **A VPS (recommended)**, e.g. DigitalOcean, Hetzner, Lightsail. It's the only
  option where *everything* works, because NocaSIEM must receive raw UDP/TCP
  syslog traffic. Run it under a process manager (`pm2`, systemd), put
  **Caddy** or **Nginx** in front for HTTPS on port 443 (proxy WebSocket
  upgrades for `/ws`), and open UDP 5514 / TCP 5515 in the firewall only to
  the IPs of your devices.
- **Render / Railway / Fly.io** work for the website, API and live feed.
  Attach a persistent disk and set `DATA_FILE` to it. Most of these platforms
  only route HTTP(S), so the syslog ports won't be reachable from the internet
  (Fly.io can expose UDP/TCP with extra config).
- **Vercel / Netlify static hosting won't work.** This app needs a long-running
  server for WebSockets and log listeners.

### Before going public

- Use HTTPS. Login tokens travel in request headers.
- Set a fresh `JWT_SECRET`.
- Set `ADMIN_EMAIL` before the first start on a public server, then
  `ALLOW_REGISTRATION=false` once your account exists.
- Set `TRUST_PROXY=1` only when a proxy is in front of the app (never when
  clients connect directly, or they could fake their IP to dodge rate limits).
- Firewall the syslog ports to your devices' IPs. UDP source addresses can be
  spoofed, so an open UDP port lets anyone inject fake log lines for a
  registered IP.
- Never commit `.env` or `data.json` (both are gitignored).
- Storage is a single JSON file, which is fine for a personal or small team
  instance. For heavy log volume, swap `server/db.js` for a real database;
  routes only talk to that module.

## How it works

- **One ingest port per protocol, many sources.** Like Splunk or Wazuh, a
  small number of fixed collector ports receive from every device. Point UDP
  sources at `INGEST_PORT` and TCP sources at `INGEST_TCP_PORT`. The IP you
  register per source is used to match incoming traffic and mark it active.
- **Alerts vs. logs.** Every incoming line is stored as a log and run through
  `server/utils/rules.js`; matches (e.g. "failed password" → Brute force
  attempt, High) become alerts.
- **Correlation / escalation.** 5+ matches of the same rule from the same IP
  within 2 minutes escalate to Critical. Tune `CORRELATION_WINDOW_MS` /
  `CORRELATION_THRESHOLD` in `rules.js`, or add your own rules.
- **Data visibility.** Admins see every log and alert. Regular users only see
  logs, alerts, stats and live events from source IPs they registered.
- **Connectivity testing.** `POST /api/sources/:id/test` opens a TCP
  connection to the registered IP:port. UDP is connectionless, so that case
  returns `reachable: null` with an explanation.
- **Login protection.** An IP+email pair is locked out for 10 minutes after
  5 failed logins.
- **Audit log.** Sign-ups, logins, profile/password changes, source changes
  and admin actions are recorded.
- **Admin panel.** The first account registered becomes `admin`. Admins can
  promote/demote, suspend/reactivate and delete accounts. Passwords are
  bcrypt hashes and are never exposed, not even to admins. You can't suspend,
  demote or delete yourself, and the last admin can't be removed.

## API reference

Authenticated requests need `Authorization: Bearer <token>`.

| Method | Path                        | Auth  | Description                               |
|--------|-----------------------------|-------|-------------------------------------------|
| GET    | /api/health                 | no    | Health check                              |
| GET    | /api/config                 | no    | Sign-up availability and ingest ports     |
| POST   | /api/auth/register          | no    | Create an account                         |
| POST   | /api/auth/login             | no    | Get a JWT (locked after 5 failures)       |
| GET    | /api/auth/me                | yes   | Current user                              |
| PATCH  | /api/auth/me                | yes   | Update `username`/`email`                 |
| PATCH  | /api/auth/password          | yes   | `{currentPassword, newPassword}`          |
| GET    | /api/sources                | yes   | List your log sources                     |
| POST   | /api/sources                | yes   | Add `{name, ip, port, protocol}`          |
| DELETE | /api/sources/:id            | yes   | Remove a source                           |
| POST   | /api/sources/:id/test       | yes   | Test IP:port reachability                 |
| GET    | /api/stats                  | yes   | KPIs, 24h volume, severity, top IPs       |
| GET    | /api/alerts                 | yes   | Recent alerts                             |
| PATCH  | /api/alerts/:id             | yes   | `{status: Open\|Investigating\|Resolved}` |
| GET    | /api/logs                   | yes   | Recent raw log lines                      |
| GET    | /api/audit-log              | yes   | Your recent account activity              |
| GET    | /api/admin/users            | admin | All users (no password data)              |
| PATCH  | /api/admin/users/:id/role   | admin | `{role: "admin"\|"user"}`                 |
| PATCH  | /api/admin/users/:id/status | admin | `{status: "active"\|"suspended"}`         |
| DELETE | /api/admin/users/:id        | admin | Delete an account and its sources         |
| GET    | /api/admin/audit-log        | admin | Every user's activity                     |
| WS     | /ws                         | yes   | Live `log`/`alert` events                 |

The WebSocket requires authentication: send `{"type":"auth","token":"<jwt>"}`
as the first message and wait for `{"type":"ready"}`.
