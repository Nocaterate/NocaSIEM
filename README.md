# NocaSIEM

A self-hosted security dashboard (SIEM) that collects logs from your devices,
raises alerts when something looks like an attack, and shows it all on a
live-updating dashboard. It's one project, run by one Node.js server.

- User accounts with an admin panel
- Real UDP/TCP syslog collection from routers, firewalls, servers and NAS boxes
- Rule-based alerts with escalation (e.g. repeated failed logins → Critical)
- Live dashboard with charts, alert triage and a streaming log view

**Contents:**
1. [Quick start](#quick-start)
2. [Getting logs into NocaSIEM](#getting-logs-into-nocasiem)
3. [Configuration](#configuration)
4. [Deploying](#deploying)
5. [How it works](#how-it-works)
6. [API reference](#api-reference)

```
server/          Express API, WebSocket live feed, syslog listeners
  server.js      entry point - also serves the dashboard
  db.js          JSON-file data store
  ingest.js      UDP/TCP syslog receivers
  routes/        /api/auth, /api/sources, /api/admin, /api/stats...
  middleware/    auth + admin checks
  utils/         detection rules, rate limits, validation
src/             React dashboard
scripts/         send-test-log.js (sample events for testing)
index.html       dashboard entry page
public/          static assets
.env             your settings (copy from .env.example, never commit)
data.json        accounts, sources, logs and alerts (created automatically, never commit)
```

## Quick start

Requires **Node.js 20.19 or newer**.

**1. Install**

```bash
npm install
```

**2. Create your settings file**

```bash
cp .env.example .env
```

Generate a secret and paste it into `.env` as `JWT_SECRET=...`:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"
```

**3. Build and start**

```bash
npm run build
```

```bash
npm start
```

Open **http://localhost:4000**. The first account you register becomes the
**admin**.

**4. Lock it down for local use**

Once your admin account exists, add these to `.env` and restart:

```
ALLOW_REGISTRATION=false
HOST=127.0.0.1
```

- `ALLOW_REGISTRATION=false`: nobody else can sign up.
- `HOST=127.0.0.1`: the dashboard only opens on this PC. Devices can still
  send logs to the syslog ports.

**Development mode:** `npm run dev` runs everything in one process with hot
reload. Editing `src/` updates the browser instantly; editing `server/`
restarts the server. It only listens on this PC by default.

| Port (default) | What                                                    |
|----------------|---------------------------------------------------------|
| TCP 4000       | Dashboard + API + live feed (`PORT`)                    |
| UDP 5514       | Syslog from devices (`INGEST_PORT`)                     |
| TCP 5515       | Syslog over TCP from devices (`INGEST_TCP_PORT`)        |

## Getting logs into NocaSIEM

Devices send their logs (syslog) to your NocaSIEM computer. NocaSIEM stores
every line, and turns lines that match a detection rule into alerts.

> **Important:** logs are only accepted from IP addresses registered as a
> **source** in **Settings**. Anything else is silently ignored.

### Step 1: Test it on this PC

This proves everything works before you touch any real device.

1. Start NocaSIEM (`npm start`) and sign in.
2. Go to **Settings** and add a source:

   | Name      | IP address  | Port  | Protocol |
   |-----------|-------------|-------|----------|
   | This PC   | `127.0.0.1` | 5514  | UDP      |

   Test logs sent from your own PC arrive from `127.0.0.1`, so that's the IP to
   register.
3. In a second terminal, in the project folder, send sample events:

   ```bash
   npm run test-log
   ```

4. Open the **Dashboard**. You should see:
   - the lines in **Live log stream**,
   - alerts for brute force, firewall block, port scan and malware,
   - the source marked **Active** in Settings.

To see an escalation, send 6 failed logins in a row. The later ones become
**Critical**:

```bash
npm run test-log -- --brute-force
```

### Step 2: Connect a real device

1. **Find this PC's IP address.** On Windows run `ipconfig` and note the
   **IPv4 Address** (e.g. `192.168.1.20`). On macOS/Linux use `ip addr` or
   `ifconfig`.
2. **Register the device** in **Settings** using **the device's own IP
   address** (check your router's list of connected devices). Port `514`,
   protocol `UDP`.
3. **Point the device's syslog at NocaSIEM:** your PC's IP, port **5514**,
   protocol **UDP**.

| Device | Where to configure it |
|--------|-----------------------|
| Router / firewall / NAS | Admin page → look for **System Log**, **Remote Syslog** or **Log Server**. Enter your PC's IP and port 5514. |
| Linux server | Create `/etc/rsyslog.d/90-nocasiem.conf` containing `*.* @192.168.1.20:5514` (your PC's IP; use `@@` for TCP port 5515), then `sudo systemctl restart rsyslog`. |
| Windows PC | Windows doesn't send syslog on its own. Install a forwarder such as NXLog Community Edition and send to your PC's IP, port 5514. |

**Windows Firewall:** the first time NocaSIEM starts, Windows asks whether to
allow Node.js. Allow **Private networks** only, not Public. If you dismissed
the prompt, open *Windows Defender Firewall → Allow an app through the
firewall* and tick **Private** for Node.js.

### What triggers an alert

Every line is stored as a log. A line becomes an alert when it contains one of
these patterns (case-insensitive). The rules live in `server/utils/rules.js`.

| Contains | Alert | Severity |
|----------|-------|----------|
| malware, ransomware, trojan, exploit | Malware signature match | Critical |
| unauthorized, privilege escalation, root access | Privilege escalation | Critical |
| brute force, failed password, authentication failure | Brute force attempt | High |
| port scan, nmap, masscan | Port scan detected | High |
| dns tunnel | DNS tunneling suspected | High |
| unusual outbound, data exfil | Unusual outbound traffic | Medium |
| denied, blocked, dropped | Firewall rule violation | Medium |

**Escalation:** 5 or more matches of the same rule from the same IP within 2
minutes are raised as **Critical**.

### Troubleshooting

| Problem | Fix |
|---------|-----|
| Nothing appears at all | The source IP in Settings must **exactly** match the device sending the logs (`127.0.0.1` for `npm run test-log`). |
| Works on this PC, not from other devices | Allow Node.js on **Private networks** in Windows Firewall, and make sure the device sends to this PC's IPv4 address, not `localhost`. |
| Device sends but nothing arrives | Check the device uses port **5514** (not the syslog default 514) and UDP. |
| Logs appear but no alerts | Normal: only lines matching a rule above become alerts. |
| Some lines missing during a flood | Each source is limited to 100 lines/second (`INGEST_RATE_LIMIT`). |

## Configuration

Set these in `.env` locally, or as environment variables on your host.

| Variable             | Required | Notes |
|----------------------|----------|-------|
| `JWT_SECRET`         | yes      | 32+ random characters (see Quick start). Changing it signs everyone out. |
| `ALLOW_REGISTRATION` | recommended | Set to `false` after creating your admin account so nobody else can sign up. |
| `HOST`               | recommended locally | `127.0.0.1` keeps the dashboard private to this PC. `npm run dev` already defaults to it; `npm start` listens on all interfaces unless set. |
| `ADMIN_EMAIL`        | recommended for new deploys | Only this email can create the first (admin) account on an empty instance. |
| `INGEST_ALLOW_UNREGISTERED` | no | Default `false`: log lines from IPs not registered as a source are dropped. |
| `INGEST_RATE_LIMIT`  | no       | Max log lines per second per source IP (default 100). |
| `DATA_FILE`          | recommended in production | Path on a **persistent** disk, e.g. `/data/nocasiem.json`. Defaults to `data.json` in the project folder. |
| `TRUST_PROXY`        | behind a proxy | `1` when behind Nginx/Caddy/a PaaS load balancer, so rate limits use real client IPs. Never set it otherwise. |
| `PORT`               | no       | Dashboard/API port (default 4000). |
| `INGEST_PORT`, `INGEST_TCP_PORT` | no | Syslog listener ports (default 5514 / 5515). |
| `CORS_ORIGIN`        | no       | Only if you host the dashboard on a different domain. |

## Deploying

Running on your own PC (above) is the simplest setup. To make it reachable
from the internet:

Build command: `npm install && npm run build` · Start command: `npm start`

(If your host installs with `NODE_ENV=production`, use
`npm install --include=dev && npm run build` so Vite is available for the build.)

- **A Linux server / VPS (recommended).** For example Google Cloud's always-free
  e2-micro, DigitalOcean or Hetzner. It's the only option where *everything*
  works, because NocaSIEM must receive raw UDP/TCP syslog traffic. Run it
  under a process manager (`pm2`, systemd), put **Caddy** or **Nginx** in front
  for HTTPS (proxy WebSocket upgrades for `/ws`), and open UDP 5514 / TCP 5515
  in the firewall only to your devices' IPs.
- **Render / Railway / Fly.io** can run the dashboard, API and live feed with a
  persistent disk (`DATA_FILE`), but usually can't receive syslog from the
  internet. Free plans without a persistent disk lose all data on restart.
- **Vercel / Netlify won't work.** NocaSIEM needs a long-running server for
  saved data, the live feed and the syslog listeners.

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

- **One ingest port per protocol, many sources.** Like Splunk or Wazuh, a few
  fixed collector ports receive from every device. The IP registered per
  source matches incoming traffic, marks the source active, and decides who
  can see its logs.
- **Data visibility.** Admins see every log and alert. Regular users only see
  logs, alerts, stats and live events from source IPs they registered. Each
  IP can belong to only one account.
- **Connectivity testing.** The **Test** button on a TCP source makes the
  server open a TCP connection to it. Loopback, link-local and reserved
  addresses are blocked, and only admins can test private network addresses.
  UDP can't be actively tested.
- **Login protection.** Failed logins are limited per account and per IP;
  sign-in, sign-up and password changes are rate limited. Changing a password
  or suspending an account signs out all of that user's sessions.
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
| PATCH  | /api/auth/me                | yes   | Update `username`/`email` (email change needs `currentPassword`) |
| PATCH  | /api/auth/password          | yes   | `{currentPassword, newPassword}`, returns a new token |
| GET    | /api/sources                | yes   | List your log sources                     |
| POST   | /api/sources                | yes   | Add `{name, ip, port, protocol}`          |
| DELETE | /api/sources/:id            | yes   | Remove a source                           |
| POST   | /api/sources/:id/test       | yes   | Test TCP reachability                     |
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
