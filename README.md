# NocaSIEM

A self-hosted security dashboard (SIEM) that collects logs from your devices,
raises alerts when something looks like an attack, and shows it all on a
live-updating dashboard. It's one project, run by one Node.js server.

- Real UDP/TCP syslog collection from Windows (via NXLog), Linux servers,
  routers and firewalls (UFW/iptables, pfSense/OPNsense, MikroTik) and web servers
- **Log decoders** that extract the attacker IP, user, ports and action from each line
- **65 Wazuh-style detection rules** with levels 0–15, MITRE ATT&CK mapping and
  correlation (brute force, password spraying, port scans, "login succeeded
  after repeated failures", web attacks, suspicious PowerShell, log clearing...)
- **Alerts page** with filters and a detail view, **Events page** with full-text log search
- SQLite storage with configurable retention (no external database needed)
- Live dashboard, user accounts and an admin panel
- A built-in **attack simulator** (`npm run test-log`) to see it all working

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
  db.js          SQLite data store
  ingest.js      UDP/TCP syslog receivers -> detection engine -> storage
  engine/        decoders.js (log parsing), rules.js (detection rules),
                 index.js (rule evaluation + correlation), mitre.js
  routes/        /api/auth, /api/sources, /api/alerts, /api/logs, /api/admin...
  middleware/    auth + admin checks
  utils/         rate limits, validation, login lockout
src/             React dashboard (views/ = Alerts, Events, alert detail)
scripts/         send-test-log.js (attack simulator)
index.html       dashboard entry page
public/          static assets
.env             your settings (copy from .env.example, never commit)
nocasiem.db      accounts, sources, logs and alerts (created automatically, never commit)
```

## Quick start

Requires **Node.js 22.13 or newer** (for the built-in SQLite module).

> **Upgrading from an older version?** On first start, an existing `data.json`
> is imported into `nocasiem.db` automatically (accounts, sources, logs and
> alerts) and renamed to `data.json.imported`. Delete that file once you've
> checked everything works.

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
3. In a second terminal, in the project folder, run the attack simulator:

   ```bash
   npm run test-log -- --scenario all
   ```

4. Open NocaSIEM. You should see:
   - **Dashboard:** event volume, top attackers and MITRE ATT&CK techniques,
   - **Alerts:** about 50 alerts, including Critical "login succeeded after
     repeated failures". Click one to see the rule, MITRE techniques,
     extracted fields, the raw log and related alerts,
   - **Events:** every log line, searchable,
   - **Settings:** the source marked **Active**.

Run a single scenario instead of `all`:

| Scenario | Simulates |
|----------|-----------|
| `mixed` (default) | A few normal and suspicious lines of each type |
| `ssh` | SSH brute force, password spraying, then a successful root login |
| `portscan` | Firewall blocks across 20 ports from one IP |
| `web` | SQL injection, path traversal, XSS, web shell, vulnerability scanner, directory brute force |
| `windows` | RDP brute force and success, new admin account, suspicious PowerShell, shadow copy deletion, new service, log cleared |
| `linux` | sudo failures, root shell, UID 0 user, user added to `sudo` |
| `router` | MikroTik login brute force and success, pfSense blocks |

```bash
npm run test-log -- --scenario windows
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
| Windows PC | Windows doesn't send syslog on its own. Install NXLog Community Edition and use the config in [Windows setup](#windows-setup-nxlog) below. |
| pfSense / OPNsense | *Status → System Logs → Settings → Remote Logging*: your PC's IP and port 5514, log "Firewall events". |
| MikroTik | *System → Logging → Actions*: add a `remote` action to your PC's IP port 5514, then log `firewall`, `account` and `system` topics to it. Add `log=yes` to firewall rules you want to see. |
| Web server (Nginx/Apache) | Send access logs via syslog, e.g. Nginx `access_log syslog:server=192.168.1.20:5514 combined;` |

### Windows setup (NXLog)

NocaSIEM reads Windows events as JSON. In `C:\Program Files\nxlog\conf\nxlog.conf`
(replace `192.168.1.20` with the IP of the PC running NocaSIEM):

```
<Extension json>
    Module  xm_json
</Extension>

<Input eventlog>
    Module  im_msvistalog
    <QueryXML>
        <QueryList>
            <Query Id="0">
                <Select Path="Security">*</Select>
                <Select Path="System">*[System[(EventID=7045)]]</Select>
                <Select Path="Microsoft-Windows-PowerShell/Operational">*[System[(EventID=4104)]]</Select>
                <Select Path="Microsoft-Windows-Windows Defender/Operational">*</Select>
            </Query>
        </QueryList>
    </QueryXML>
    Exec    to_json();
</Input>

<Output nocasiem>
    Module  om_tcp
    Host    192.168.1.20
    Port    5515
</Output>

<Route r>
    Path    eventlog => nocasiem
</Route>
```

Register the Windows PC in **Settings** with protocol **TCP** (TCP handles large
PowerShell events better than UDP), then restart the NXLog service.

For the process and PowerShell rules to work, enable in Group Policy:
*Audit Process Creation* (with "Include command line in process creation
events") and *Turn on PowerShell Script Block Logging*.

**Windows Firewall:** the first time NocaSIEM starts, Windows asks whether to
allow Node.js. Allow **Private networks** only, not Public. If you dismissed
the prompt, open *Windows Defender Firewall → Allow an app through the
firewall* and tick **Private** for Node.js.

### How detection works

Every incoming line goes through three steps:

1. **Decode.** `server/engine/decoders.js` parses the syslog header and runs a
   decoder for the program that sent it, extracting fields such as `srcip`
   (the attacker), `user`, `dstport` and `action`.

   | Decoder | Understands |
   |---------|-------------|
   | `sshd` | failed/accepted logins, invalid users, probes |
   | `sudo`, `su`, `accounts` | sudo commands and failures, su, user/group/password changes |
   | `firewall` | UFW, iptables and most Linux-based routers (`SRC=… DST=… DPT=…`) |
   | `pfsense` | pfSense / OPNsense `filterlog` |
   | `mikrotik` | RouterOS firewall logs and login success/failure |
   | `web-access` | Nginx / Apache combined access logs |
   | `windows` | Windows events as JSON (NXLog), with Security, System, PowerShell and Defender event IDs |
   | `json`, `generic` | any other JSON or text line (IP and user extracted when possible) |

2. **Match rules.** `server/engine/rules.js` holds 65 rules. Each has a
   **level** from 0 to 15 and MITRE ATT&CK techniques:

   | Level | Severity | Examples |
   |-------|----------|----------|
   | 0–3 | Informational (stored, no alert) | successful logins, firewall blocks, sudo commands |
   | 4–6 | Low | single failed login, XSS attempt, scanner user agent |
   | 7–9 | Medium | SQL injection, root shell via sudo, new user account |
   | 10–12 | High | brute force, password spraying, port scan, admin group change, suspicious PowerShell |
   | 13–15 | Critical | login succeeded after repeated failures, security log cleared |

3. **Correlate.** Rules can look across events:
   - **Frequency:** e.g. 8 failed SSH logins from the same IP in 2 minutes,
     or connections to 15 different ports in 1 minute.
   - **Sequence:** e.g. a successful login from an IP that just failed 5 times.
   - **Ignore:** repeats of noisy rules (like a vulnerability scanner) raise
     one alert per IP instead of hundreds.

The highest-level match becomes the alert. Browse all rules with
`GET /api/rules`.

**Adding your own rule:** append an object to `RULES` in
`server/engine/rules.js` with an id of 100000 or higher, for example:

```js
{ id: 100001, level: 8, description: "Login to the backup account", decoder: "sshd",
  action: "ssh_login_success", field: { user: "backup" }, groups: ["authentication_success"], mitre: ["T1078"] },
```

### Troubleshooting

| Problem | Fix |
|---------|-----|
| Nothing appears at all | The source IP in Settings must **exactly** match the device sending the logs (`127.0.0.1` for `npm run test-log`). |
| Works on this PC, not from other devices | Allow Node.js on **Private networks** in Windows Firewall, and make sure the device sends to this PC's IPv4 address, not `localhost`. |
| Device sends but nothing arrives | Check the device uses port **5514** (not the syslog default 514) and UDP. |
| Logs appear but no alerts | Normal: only rules of level 4+ create alerts. Open the line in **Events** to see which decoder and rules matched. |
| Windows events show as `generic` | NXLog isn't sending JSON: check the `Exec to_json();` line in the config. |
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
| `DB_FILE`            | recommended in production | SQLite database path on a **persistent** disk, e.g. `/data/nocasiem.db`. Defaults to `nocasiem.db` in the project folder. |
| `LOG_RETENTION_DAYS` | no       | Days to keep raw logs (default 90). |
| `ALERT_RETENTION_DAYS` | no     | Days to keep alerts (default 365). |
| `ALERT_MIN_LEVEL`    | no       | Minimum rule level that creates an alert (default 4). |
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
  persistent disk (`DB_FILE`), but usually can't receive syslog from the
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
- Never commit `.env` or `nocasiem.db` (both are gitignored).
- Storage is a single SQLite file, which comfortably handles a home lab or
  small office. For very high log volume, swap `server/db.js` for a dedicated
  database; routes only talk to that module.

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
| GET    | /api/alerts                 | yes   | Search alerts: `q, severity, status, srcIp, sourceIp, user, mitre, ruleId, levelMin, from, to, before, limit` |
| GET    | /api/alerts/:id             | yes   | Alert with its log line, rule and related alerts |
| PATCH  | /api/alerts/:id             | yes   | `{status: Open\|Investigating\|Resolved}` |
| GET    | /api/logs                   | yes   | Search logs: `q` (full text), `srcIp, sourceIp, user, decoder, action, from, to, before, limit` |
| GET    | /api/logs/:id               | yes   | One log line with extracted fields        |
| GET    | /api/rules                  | yes   | Detection rule catalogue                  |
| GET    | /api/audit-log              | yes   | Your recent account activity              |
| GET    | /api/admin/users            | admin | All users (no password data)              |
| PATCH  | /api/admin/users/:id/role   | admin | `{role: "admin"\|"user"}`                 |
| PATCH  | /api/admin/users/:id/status | admin | `{status: "active"\|"suspended"}`         |
| DELETE | /api/admin/users/:id        | admin | Delete an account and its sources         |
| GET    | /api/admin/audit-log        | admin | Every user's activity                     |
| WS     | /ws                         | yes   | Live `log`/`alert` events                 |

The WebSocket requires authentication: send `{"type":"auth","token":"<jwt>"}`
as the first message and wait for `{"type":"ready"}`.
