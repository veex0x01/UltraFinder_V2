# GetVeex

```

       ██████╗ ███████╗████████╗██╗   ██╗███████╗███████╗  ██╗     ██╗
       ██╔════╝ ██╔════╝╚══██╔══╝██║   ██║██╔════╝██╔════╝ ╚██╗  ██╔╝
       ██║  ███╗█████╗     ██║   ██║   ██║█████╗  █████╗      ╚███╔╝ 
       ██║   ██║██╔══╝     ██║   ╚██╗ ██╔╝██╔══╝  ██╔══╝      ██╔██╗ 
       ╚██████╔╝███████╗   ██║    ╚████╔╝ ███████╗███████╗ ██╔╝     ██╗
        ╚═════╝ ╚══════╝   ╚═╝     ╚═══╝  ╚══════╝╚══════╝ ╚═╝      ╚═╝
  A D V A N C E D   O F F E N S I V E   S E C U R I T Y   S U I T E
```

**GetVeex v2.0.0** — All-in-one offensive security toolkit built in Go.
Crawl, hunt, scan, fuzz, and monitor targets from a single binary.

**Author:** veex0x01

![Screenshot](s2.png)

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Cheatsheet](#cheatsheet)
- [Commands](#commands)
  - [scan](#1-scan--crawl--recon)
  - [hunt](#2-hunt--sensitive-data-scanner)
  - [pipeline](#3-pipeline--yaml-workflows)
  - [auth](#4-auth--authentication-testing)
  - [proxy](#5-proxy--mitm-intercepting-proxy)
  - [monitor](#6-monitor--change-detection)
  - [webui](#7-webui--mission-control-dashboard)
  - [techdetect](#8-techdetect--technology-fingerprinting)
- [Pipeline Configs](#pipeline-configs)
- [Hunter Patterns](#hunter--pattern-list)
- [Output Types](#output-types)
- [Output Files](#output-files)
- [Disclaimer](#disclaimer)

---

## Features

### Core Recon

- Fast async web crawling with configurable depth and concurrency
- JavaScript endpoint extraction from JS files
- Sensitive parameter detection in URLs and forms
- Hidden form field discovery
- Subdomain extraction from response bodies
- AWS S3 bucket detection
- AJAX/XHR endpoint parsing
- WAF/CDN detection (Cloudflare, AWS WAF, Akamai, Imperva)
- Backup file discovery
- Source map parsing

### Hunter (Sensitive Data Scanner)

- 38+ regex patterns for detecting secrets in web content
- Auto-crawl + hunt in a single command (`hunt -t`)
- Supports AWS keys, Google/GitHub/Slack/Stripe tokens, private keys, JWTs, credentials, PII, and more
- Concurrent scanning with configurable workers
- Severity filtering (CRITICAL, HIGH, MEDIUM, LOW)
- Detailed findings report with line numbers and categories

### Smart Recon & Vuln Hunting

- **TechFinder**: Chrome-based technology detection (CMS, frameworks, servers)
- **SmartNuclei**: Maps detected technologies to specific CVE templates
- **Shodan Integration**: Fetches CVEs from Shodan InternetDB (no API key needed)
- **SQLMap Integration**: Automated SQL injection testing
- **Dalfox Integration**: XSS hunting on parameterized URLs
- **LFIMap Integration**: Local file inclusion testing

### Auth Testing

- IDOR vulnerability scanning
- Privilege escalation detection
- Authentication bypass testing
- MITM intercepting proxy with auto-test

### Monitoring

- Continuous change detection with configurable intervals
- Screenshot comparison
- Content diff monitoring
- Notifications: Telegram, Slack, Discord, generic webhooks

### External Sources

- Wayback Machine integration
- CommonCrawl data fetching
- AlienVault OTX threat intelligence

### Stealth Mode

- Random User-Agent rotation
- Request delay randomization
- Browser-like header simulation

### Reporting

- HTML reports
- JSON / JSONL export
- CSV export
- Pipeline logging

### Web UI (Mission Control)

- Red Team dashboard with dark theme
- 4 scan modes from the browser: Crawl, Hunter, Pipeline, Auth
- Full configuration panels — every CLI flag available in the UI
- Live terminal log streaming via WebSocket
- Operation history with type badges and status tracking
- Intelligence report with severity and type filtering
- Optional basic auth protection

---

## Installation

```bash
git clone <repo-url>
cd GetVeex
go mod tidy
go build -o GetVeex .
```

**Optional dependencies** (for pipeline steps):

| Tool                                                    | Purpose                         |
| ------------------------------------------------------- | ------------------------------- |
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration           |
| [Amass](https://github.com/owasp-amass/amass)              | Subdomain enumeration           |
| [httpx](https://github.com/projectdiscovery/httpx)         | HTTP probing                    |
| [Nuclei](https://github.com/projectdiscovery/nuclei)       | Vulnerability scanning          |
| [Katana](https://github.com/projectdiscovery/katana)       | Web crawling                    |
| [Dalfox](https://github.com/hahwul/dalfox)                 | XSS scanning                    |
| [SQLMap](https://sqlmap.org/)                              | SQL injection                   |
| [Nmap](https://nmap.org/)                                  | Port scanning                   |
| `techFinder/techfinder`                               | Technology detection (included) |

> The `scan` and `hunt` commands work standalone with **zero external dependencies**.

---

## Cheatsheet

Quick copy-paste commands for common workflows. Replace `target.com` with your target.

### Recon & Crawling

```bash
# Quick crawl (default depth 2, 10 threads)
./GetVeex scan -u https://target.com

# Deep stealth crawl with all passive sources
./GetVeex scan -u https://target.com -d 3 -t 20 --stealth --deep --all-sources --subs

# Crawl through Burp proxy
./GetVeex scan -u https://target.com -p http://127.0.0.1:8080

# Crawl with custom cookies and headers
./GetVeex scan -u https://target.com -c "session=abc123" -H "X-API-Key: key123"

# Export results as JSON
./GetVeex scan -u https://target.com --deep -o results.json --json

# Everything - ultimate command to test everything
./GetVeex pipeline -f configs/ultimate.yaml -t https://target.com

# for auth stuff -all
./GetVeex auth -t https://target.com --header-attack --bypass --idor --privesc
```

### Secret Hunting

```bash
# Auto-crawl + hunt for secrets (one command)
./GetVeex hunt -t https://target.com

# Hunt HIGH/CRITICAL only with 20 workers
./GetVeex hunt -t https://target.com --severity HIGH -w 20

# Deep crawl + hunt (depth 5)
./GetVeex hunt -t https://target.com -d 5 -w 20

# Hunt from a URL list
./GetVeex hunt -i urls.txt -o ./loot

# Hunt specific JS files
./GetVeex hunt -u https://target.com/static/app.js -u https://target.com/config.json
```

### Pipeline Workflows

```bash
# Smart hunt — tech detect + shodan + smart nuclei + crawl
./GetVeex pipeline -f configs/smart_hunt.yaml -t target.com --scope exact

# Full recon — subfinder + amass + httpx + crawl + nuclei + dalfox + sqlmap
./GetVeex pipeline -f configs/full_recon.yaml -t target.com

# Quick scan — probe + nuclei (critical/high only)
./GetVeex pipeline -f configs/quick_scan.yaml -t target.com

# XSS focused — enum + crawl + param filter + dalfox
./GetVeex pipeline -f configs/xss_hunt.yaml -t target.com

# Subdomain enum — subfinder + amass + httpx + nmap
./GetVeex pipeline -f configs/subdomain_enum.yaml -t target.com

# Hunter pipeline — subfinder + probe + crawl + hunter
./GetVeex pipeline -f configs/hunter_scan.yaml -t target.com

# Pro hunter — probe + deep crawl + hunter (MEDIUM+ severity)
./GetVeex pipeline -f configs/pro_hunter.yaml -t target.com

# With full report export
./GetVeex pipeline -f configs/smart_hunt.yaml -t target.com \
  --html report.html --json-export data.json --csv-export data.csv
```

### Auth Testing

```bash
# IDOR test — compare responses between admin and user sessions
./GetVeex auth -t https://target.com/api/user/1 \
  --high-session "Cookie: session=admin_token" \
  --low-session "Cookie: session=user_token" --idor

# Privilege escalation — can low-priv user access admin paths?
./GetVeex auth -t https://target.com/admin \
  --high-session "Cookie: session=admin" \
  --low-session "Cookie: session=user" --privesc

# Auth bypass — try header tricks, path traversal, verb tampering
./GetVeex auth -t https://target.com/admin --bypass

# Full auth test suite
./GetVeex auth -t https://target.com/api \
  --high-session "Cookie: session=admin" \
  --low-session "Cookie: session=user" \
  --idor --privesc --bypass
```

### Monitoring

```bash
# Monitor with Telegram alerts every 30 min
./GetVeex monitor -t https://target.com --interval 30m --diff --screenshot \
  --telegram-token "BOT_TOKEN" --telegram-chat "CHAT_ID"

# Monitor with Slack alerts every hour
./GetVeex monitor -t https://target.com --interval 1h --diff \
  --slack-webhook "https://hooks.slack.com/services/..."

# Monitor with Discord alerts
./GetVeex monitor -t https://target.com --interval 1h --diff \
  --discord-webhook "https://discord.com/api/webhooks/..."

# One-shot diff check (no loop)
./GetVeex monitor -t https://target.com --diff --once
```

### Web UI

```bash
# Launch dashboard (open http://localhost:8080)
./GetVeex webui

# Custom port with auth
./GetVeex webui -l :9090 --auth-user admin --auth-pass s3cret
```

### Proxy

```bash
# Start MITM proxy
./GetVeex proxy

# Scoped proxy with auto-testing
./GetVeex proxy -l :9090 -s target.com --auto-test
```

### Tech Detection & CVE Mapping

Standalone tech detection command — fingerprints web servers, CMS, frameworks, WAFs, and maps to CVEs.

```bash
# Quick tech detection (built-in fingerprinting)
./GetVeex techdetect -t https://target.com

# Deep scan with TechFinder (Chrome-based, more accurate)
./GetVeex techdetect -t https://target.com --deep

# Deep scan + CVE lookup
./GetVeex techdetect -t https://target.com --deep --cve

# JSON output (pipe to jq, save to file, feed to other tools)
./GetVeex techdetect -t https://target.com --deep --cve --json

# Scan multiple targets
./GetVeex techdetect -t https://target.com -t https://other.com --deep --cve

# Quiet mode (no banner)
./GetVeex techdetect -t https://target.com --deep --cve -q
```

**Tech detection via pipeline** (deeper analysis with TechFinder + SmartNuclei):

```bash
# Smart hunt pipeline — TechFinder + Shodan CVEs + SmartNuclei (best for full recon)
./GetVeex pipeline -f configs/smart_hunt.yaml -t testphp.vulnweb.com --scope exact

# Smart hunt with report export
./GetVeex pipeline -f configs/smart_hunt.yaml -t testphp.vulnweb.com --scope exact \
  --html tech_report.html --json-export tech_data.json
```

**Pipeline tech detection flow:**

```
Subfinder (if scope != exact)
  └─ Simple Probe (live filter + basic tech fingerprint)
       ├─ TechFinder (Chrome-based: CMS, frameworks, servers, CPE)
       ├─ Shodan InternetDB (CVE lookup — no API key needed)
       ├─ GetVeex Crawler (endpoint + JS + param discovery)
       │    └─ ParamFilter (extract attack URLs)
       └─ SmartNuclei (maps detected tech → specific CVE templates)
```

**What gets detected:**

- Web servers (Apache, Nginx, IIS, LiteSpeed)
- CMS/Frameworks (WordPress, Joomla, Drupal, Laravel, Django, React, Angular, Vue)
- Programming languages (PHP, Python, Node.js, Java, ASP.NET)
- WAF/CDN (Cloudflare, AWS WAF, Akamai, Imperva)
- Databases (MySQL, PostgreSQL, MongoDB, Redis)
- JavaScript libraries and versions
- CPE identifiers for CVE correlation

### Common Combos

```bash
# Full target assessment: crawl + hunt + smart pipeline + report
./GetVeex scan -u https://target.com -d 3 --deep --stealth -o crawl.json --json
./GetVeex hunt -t https://target.com --severity HIGH -w 20
./GetVeex pipeline -f configs/smart_hunt.yaml -t target.com \
  --html report.html --json-export data.json

# Bug bounty quick wins: hunt secrets + XSS + SQLi
./GetVeex hunt -t https://target.com --severity MEDIUM -w 30
./GetVeex pipeline -f configs/xss_hunt.yaml -t target.com
./GetVeex pipeline -f configs/full_recon.yaml -t target.com --html findings.html

# Subdomain takeover check: enum + probe
./GetVeex pipeline -f configs/subdomain_enum.yaml -t target.com

# Continuous monitoring: set and forget
./GetVeex monitor -t https://target.com --interval 1h --diff --screenshot \
  --telegram-token "TOKEN" --telegram-chat "ID"
```

---

## Commands

### 1. `scan` — Crawl & Recon

Deep web crawling with endpoint discovery, parameter analysis, and secret detection.

```bash
# Basic crawl
./GetVeex scan -u https://target.com

# Deep stealth crawl
./GetVeex scan -u https://target.com -d 3 -t 20 --stealth --deep

# Full recon with all external sources
./GetVeex scan -u https://target.com -d 3 -t 20 --stealth --deep --all-sources --subs -o results.txt

# With Burp Suite proxy
./GetVeex scan -u https://target.com -p http://127.0.0.1:8080

# JSON output
./GetVeex scan -u https://target.com --deep -o results.json --json
```

**Scan Flags:**

| Flag                 | Description                      | Default |
| -------------------- | -------------------------------- | ------- |
| `-u, --url`        | Target URL (required)            | -       |
| `-d, --depth`      | Maximum crawl depth              | 2       |
| `-t, --threads`    | Concurrent threads               | 10      |
| `-m, --timeout`    | Request timeout (seconds)        | 30      |
| `-k, --delay`      | Delay between requests (seconds) | 0       |
| `--random-delay`   | Random delay jitter (ms)         | 0       |
| `-p, --proxy`      | Proxy URL (e.g. Burp)            | -       |
| `-c, --cookie`     | Cookie string                    | -       |
| `-H, --header`     | Custom header (repeatable)       | -       |
| `-a, --user-agent` | Custom User-Agent                | -       |
| `--no-redirect`    | Disable following redirects      | false   |
| `--stealth`        | Enable stealth mode              | false   |
| `--random-ua`      | Random User-Agent per request    | false   |
| `--deep`           | Enable deep analysis             | false   |
| `--subs`           | Include subdomains               | false   |
| `--wayback`        | Fetch from Wayback Machine       | false   |
| `--commoncrawl`    | Fetch from CommonCrawl           | false   |
| `--otx`            | Fetch from AlienVault OTX        | false   |
| `--all-sources`    | Fetch from all sources           | false   |
| `-o, --output`     | Output file path                 | -       |
| `--json`           | JSON output format               | false   |
| `-v, --verbose`    | Verbose output                   | false   |
| `-q, --quiet`      | Suppress console output          | false   |

---

### 2. `hunt` — Sensitive Data Scanner

Scans web endpoints for API keys, secrets, credentials, private keys, PII, and more using 38+ regex patterns. Can auto-crawl a target or accept a list of URLs.

```bash
# Auto-crawl a target and hunt (recommended)
./GetVeex hunt -t https://target.com

# Hunt with HIGH severity only, 20 workers
./GetVeex hunt -t https://target.com --severity HIGH -w 20

# Deeper crawl (depth 5)
./GetVeex hunt -t https://target.com -d 5 -w 20

# Hunt from a file of URLs
./GetVeex hunt -i urls.txt -o ./results

# Hunt specific URLs directly
./GetVeex hunt -u https://target.com/app.js -u https://target.com/config.json

# Quiet mode (no banner)
./GetVeex hunt -t https://target.com -q
```

**Hunt Flags:**

| Flag              | Description                                   | Default              |
| ----------------- | --------------------------------------------- | -------------------- |
| `-t, --target`  | Target URL to auto-crawl and hunt             | -                    |
| `-d, --depth`   | Crawl depth when using `--target`           | 3                    |
| `-i, --input`   | Input file with URLs (one per line)           | -                    |
| `-u, --url`     | URL to scan (repeatable)                      | -                    |
| `-o, --output`  | Output directory for results                  | `./hunter_results` |
| `-w, --workers` | Number of concurrent workers                  | 10                   |
| `--severity`    | Minimum severity: CRITICAL, HIGH, MEDIUM, LOW | LOW                  |
| `-q, --quiet`   | Quiet mode (no banner/verbose)                | false                |

**Hunt Output Structure:**

```
hunter_results/
├── results/<timestamp>/
│   └── all_endpoints.txt            # All scanned URLs with status
└── sensitive_findings/<timestamp>/
    └── sensitive_data_detailed.txt   # Detailed findings with context
```

---

### 3. `pipeline` — YAML Workflows

Run multi-step attack pipelines defined in YAML config files. Steps run in dependency order with data flowing between them.

```bash
# Smart hunt (recommended) — Tech Detection + Shodan + SmartNuclei + Crawl
./GetVeex pipeline -f configs/smart_hunt.yaml -t target.com --scope exact

# Default recon — Subfinder + Probe + Internal Crawl + Nuclei
./GetVeex pipeline -f configs/default.yaml -t target.com

# Full recon — Subfinder + Amass + httpx + Crawl + Nuclei + Dalfox + SQLMap
./GetVeex pipeline -f configs/full_recon.yaml -t target.com

# Quick scan — Probe + Nuclei (critical/high only)
./GetVeex pipeline -f configs/quick_scan.yaml -t target.com

# XSS hunt — Enum + Crawl + Param filter + Dalfox
./GetVeex pipeline -f configs/xss_hunt.yaml -t target.com

# Subdomain enumeration — Subfinder + Amass + httpx + Nmap
./GetVeex pipeline -f configs/subdomain_enum.yaml -t target.com

# Hunter pipeline — Subfinder + httpx + Crawl + Hunter
./GetVeex pipeline -f configs/hunter_scan.yaml -t target.com

# With report exports
./GetVeex pipeline -f configs/smart_hunt.yaml -t target.com \
  --html report.html --json-export data.json --csv-export data.csv
```

**Pipeline Flags:**

| Flag                  | Description                                            | Default |
| --------------------- | ------------------------------------------------------ | ------- |
| `-f, --file`        | Pipeline YAML file (required)                          | -       |
| `-t, --target`      | Target URL/domain (required)                           | -       |
| `--scope`           | Scope:`all` (subs+domain) or `exact` (domain only) | all     |
| `--log`             | Log output file                                        | -       |
| `--html`            | Export HTML report                                     | -       |
| `-j, --json-export` | Export JSON report                                     | -       |
| `-c, --csv-export`  | Export CSV report                                      | -       |

**Available Pipeline Steps:**

| Step Type           | Tool       | Description                            |
| ------------------- | ---------- | -------------------------------------- |
| `subfinder`       | Subfinder  | Subdomain enumeration                  |
| `amass`           | Amass      | Subdomain enumeration (alt source)     |
| `httpx`           | httpx      | HTTP probing & live filtering          |
| `simple_probe`    | Built-in   | Manual HTTP probe + tech detect        |
| `GetVeex_crawler` | Built-in   | Deep web crawling                      |
| `katana`          | Katana     | Web crawling (external)                |
| `paramfilter`     | Built-in   | Parameter extraction & filtering       |
| `techfinder`      | TechFinder | Chrome-based tech detection            |
| `nuclei`          | Nuclei     | Vulnerability scanning                 |
| `smart_nuclei`    | Nuclei     | Tech-aware intelligent CVE scanning    |
| `shodan`          | Shodan API | CVE enumeration (free InternetDB)      |
| `dalfox`          | Dalfox     | XSS scanning                           |
| `sqlmap`          | SQLMap     | SQL injection testing                  |
| `lfimap`          | LFIMap     | Local file inclusion testing           |
| `nmap`            | Nmap       | Port scanning                          |
| `hunter`          | Built-in   | Sensitive data scanning (38+ patterns) |

---

## Pipeline Configs

| Config                          | Description                                  |
| ------------------------------- | -------------------------------------------- |
| `configs/smart_hunt.yaml`     | TechFinder + Shodan + SmartNuclei + Crawl    |
| `configs/default.yaml`        | Subfinder + Probe + Internal Crawl + Nuclei  |
| `configs/full_recon.yaml`     | Full enum + Crawl + Nuclei + Dalfox + SQLMap |
| `configs/quick_scan.yaml`     | Fast probe + Nuclei (critical/high only)     |
| `configs/xss_hunt.yaml`       | Enum + Crawl + Param filter + Dalfox         |
| `configs/subdomain_enum.yaml` | Subfinder + Amass + httpx + Nmap             |
| `configs/hunter_scan.yaml`    | Enum + Probe + Crawl + Hunter                |
| `configs/pro_hunter.yaml`     | Fast probe + Deep crawl + Hunter (MEDIUM+)   |

### Smart Hunt Pipeline Flow

```
Subfinder (if scope != exact)
    └── Simple Probe (live filter)
            ├── TechFinder (tech detection)
            ├── Shodan (CVE enumeration)
            ├── GetVeex Crawler (endpoint discovery)
            │       └── ParamFilter (attack URLs)
            └── SmartNuclei (tech-aware vuln scan)
```

---

### 4. `auth` — Authentication Testing

Test for IDOR, privilege escalation, and authentication bypass vulnerabilities.

```bash
# IDOR testing with two sessions
./GetVeex auth -t https://target.com/api/user/1 \
  --high-session "Cookie: session=admin_token" \
  --low-session "Cookie: session=user_token" \
  --idor

# Privilege escalation testing
./GetVeex auth -t https://target.com/admin \
  --high-session "Cookie: session=admin" \
  --low-session "Cookie: session=user" \
  --privesc

# Auth bypass testing
./GetVeex auth -t https://target.com/admin --bypass

# Header attacks (SSRF, IP spoofing, one-click)
./GetVeex auth -t https://target.com --header-attack

# Full auth test suite
./GetVeex auth -t https://target.com/api \
  --high-session "Cookie: session=admin" \
  --low-session "Cookie: session=user" \
  --idor --privesc --bypass --header-attack
```

**Auth Flags:**

| Flag                | Description                            |
| ------------------- | -------------------------------------- |
| `-t, --target`    | Target URL (required)                  |
| `--high-session`  | High-privilege session header          |
| `--low-session`   | Low-privilege session header           |
| `--idor`          | Test for IDOR vulnerabilities          |
| `--privesc`       | Test for privilege escalation          |
| `--bypass`        | Test for authentication bypass         |
| `--header-attack` | SSRF/IP-spoof/One-click header attacks |

---

### 5. `proxy` — MITM Intercepting Proxy

Start an intercepting proxy for manual or automated auth testing.

```bash
# Start proxy on default port
./GetVeex proxy

# Custom port with scope and auto-testing
./GetVeex proxy -l :9090 -s target.com --auto-test
```

**Proxy Flags:**

| Flag             | Description                 | Default   |
| ---------------- | --------------------------- | --------- |
| `-l, --listen` | Proxy listen address        | `:8888` |
| `-s, --scope`  | Target scope domain         | -         |
| `--auto-test`  | Auto-test captured requests | false     |

---

### 6. `monitor` — Change Detection

Monitor targets for changes with notifications via Telegram, Slack, Discord, or webhooks.

```bash
# Monitor with Telegram alerts
./GetVeex monitor -t https://target.com \
  --interval 30m --diff --screenshot \
  --telegram-token "BOT_TOKEN" \
  --telegram-chat "CHAT_ID"

# Monitor with Slack alerts
./GetVeex monitor -t https://target.com \
  --interval 1h --diff \
  --slack-webhook "https://hooks.slack.com/services/..."

# Monitor with Discord alerts
./GetVeex monitor -t https://target.com \
  --interval 1h --diff \
  --discord-webhook "https://discord.com/api/webhooks/..."

# One-time check
./GetVeex monitor -t https://target.com --diff --once
```

**Monitor Flags:**

| Flag                  | Description                                   | Default |
| --------------------- | --------------------------------------------- | ------- |
| `-t, --target`      | Target URL to monitor (required)              | -       |
| `--interval`        | Check interval (e.g.`30m`, `1h`, `24h`) | `1h`  |
| `--screenshot`      | Enable screenshot comparison                  | false   |
| `--diff`            | Enable content diff monitoring                | false   |
| `--once`            | Run once and exit                             | false   |
| `--telegram-token`  | Telegram bot token                            | -       |
| `--telegram-chat`   | Telegram chat ID                              | -       |
| `--slack-webhook`   | Slack webhook URL                             | -       |
| `--discord-webhook` | Discord webhook URL                           | -       |
| `--webhook`         | Generic webhook URL                           | -       |

---

### 7. `webui` — Mission Control Dashboard

Launch a Red Team web dashboard for managing all scan modes from your browser. Every feature available in the CLI is accessible from the UI.

```bash
# Launch on default port
./GetVeex webui

# Custom port with authentication
./GetVeex webui -l :9090 --auth-user admin --auth-pass s3cret
```

Access at **http://localhost:8080** (default).

**Web UI Flags:**

| Flag             | Description         | Default   |
| ---------------- | ------------------- | --------- |
| `-l, --listen` | Listen address      | `:8080` |
| `--auth-user`  | Basic auth username | -         |
| `--auth-pass`  | Basic auth password | -         |

**Dashboard Modes:**

| Mode                | What it does                                                                                                |
| ------------------- | ----------------------------------------------------------------------------------------------------------- |
| **CRAWL**     | Full crawling with depth, threads, stealth, deep analysis, proxy, cookies, headers, wayback/commoncrawl/OTX |
| **HUNTER**    | Auto-crawl + secret scanning with severity filter and worker count                                          |
| **PIPELINE**  | Select any YAML pipeline config, toggle steps, set threads/timeout                                          |
| **AUTH TEST** | IDOR, privilege escalation, and auth bypass testing with session headers                                    |

**Dashboard Pages:**

- **Mission Control** — Configure and launch any scan mode
- **Operation History** — Track all past and running operations with type badges
- **Intelligence** — Filter and search all discovered results by severity and type
- **Live Terminal** — Real-time WebSocket log streaming from all active scans

---

### 8. `techdetect` — Technology Fingerprinting

Standalone technology detection and CVE mapping. Fingerprints web servers, CMS, frameworks, languages, WAFs, databases, and JS libraries from HTTP responses. Use `--deep` for Chrome-based detection via TechFinder.

```bash
# Quick tech scan
./GetVeex techdetect -t https://target.com

# Deep scan (TechFinder + built-in combined)
./GetVeex techdetect -t https://target.com --deep

# With CVE lookup
./GetVeex techdetect -t https://target.com --deep --cve

# JSON output
./GetVeex techdetect -t https://target.com --deep --cve --json

# Multiple targets
./GetVeex techdetect -t https://target.com -t https://other.com --deep --cve
```

**Techdetect Flags:**

| Flag             | Description                                    | Default |
| ---------------- | ---------------------------------------------- | ------- |
| `-t, --target` | Target URL (repeatable)                        | -       |
| `--deep`       | Use TechFinder for Chrome-based deep detection | false   |
| `--cve`        | Lookup CVEs for detected technologies          | false   |
| `--json`       | JSON output                                    | false   |
| `-q, --quiet`  | Quiet mode (no banner)                         | false   |

---

## Hunter — Pattern List

The `hunt` command detects 38 pattern types across these categories:

| Category                 | Patterns                                                                                                                | Severity     |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------- | ------------ |
| **API Keys**       | AWS Access Key, AWS Secret Key, Generic API Key, Google API Key, Stripe Live Key, Stripe Restricted Key, Twilio API Key | HIGH         |
| **Tokens**         | Generic Token, GitHub Personal Access Token, GitHub App Token, Slack Token, Square Access Token, PayPal Braintree Token | HIGH         |
| **OAuth**          | Google OAuth Client ID, GitHub OAuth Token, Square OAuth Secret                                                         | MEDIUM-HIGH  |
| **Webhooks**       | Slack Webhook URL                                                                                                       | HIGH         |
| **Secrets**        | Generic Secret, TODO/FIXME mentioning secrets                                                                           | MEDIUM-HIGH  |
| **Private Keys**   | RSA, DSA, EC, PGP, OpenSSH private keys                                                                                 | CRITICAL     |
| **Credentials**    | Hardcoded passwords, DB connection strings (Postgres/MySQL/MongoDB/Redis), URLs with embedded credentials               | HIGH         |
| **Auth Tokens**    | JWT Tokens                                                                                                              | MEDIUM       |
| **Financial**      | Credit Card Numbers (Visa/MC/Amex)                                                                                      | CRITICAL     |
| **PII**            | Social Security Numbers, Email Addresses, Phone Numbers                                                                 | LOW-CRITICAL |
| **Infrastructure** | Internal IPs (RFC1918), Firebase URLs, AWS S3 Buckets                                                                   | MEDIUM       |
| **Crypto**         | Bitcoin Addresses, Ethereum Addresses                                                                                   | MEDIUM       |
| **Encoded**        | Base64 high-entropy strings                                                                                             | LOW          |

---

## Output Types

Tags used in scan output:

| Tag                   | Description                                 |
| --------------------- | ------------------------------------------- |
| `[technology]`      | Detected technology (CMS, Server, Language) |
| `[cve]`             | Vulnerability (Shodan / Nuclei)             |
| `[href]`            | HTML links                                  |
| `[form]`            | Form actions                                |
| `[js]`              | JavaScript files                            |
| `[linkfinder]`      | URLs extracted from JS                      |
| `[sensitive-param]` | Sensitive parameters                        |
| `[hidden-field]`    | Hidden form fields                          |
| `[api-key]`         | Detected secrets                            |
| `[ajax-endpoint]`   | AJAX/XHR endpoints                          |
| `[waf-detected]`    | WAF/CDN detection                           |
| `[backup-probe]`    | Backup files                                |
| `[subdomain]`       | Discovered subdomains                       |
| `[aws-s3]`          | S3 buckets                                  |

---

## Output Files

### Scan Results

Saved in `results/<target>/`:

- `results.json` — Full structured data
- `crawled_urls.txt` — All discovered URLs
- `params.txt` — Unique parameters found
- `secrets.txt` — API keys and secrets
- `vulnerabilities.txt` — Nuclei & Shodan findings

### Hunter Results

Saved in `hunter_results/`:

- `results/<timestamp>/all_endpoints.txt` — All scanned endpoints with status
- `sensitive_findings/<timestamp>/sensitive_data_detailed.txt` — Detailed findings with severity, category, line numbers

### Pipeline Reports

Generated with export flags:

- `--html report.html` — Full HTML report
- `--json-export data.json` — Structured JSON export
- `--csv-export data.csv` — CSV for spreadsheet analysis

---

## Quick Start

```bash
# 1. Build
go build -o GetVeex .

# 2. First crawl
./GetVeex scan -u https://target.com

# 3. Hunt for secrets
./GetVeex hunt -t https://target.com

# 4. Full automated recon
./GetVeex pipeline -f configs/smart_hunt.yaml -t target.com --scope exact

# 5. Open the dashboard
./GetVeex webui
```

See the [Cheatsheet](#cheatsheet) above for more workflows and combos.

---

## Sponsor

If you find this tool useful, consider supporting development:

[Support via PayPal](https://www.paypal.com/ncp/payment/BNSJG52TFE5B2)

---

## Disclaimer

This tool is for **authorized security testing only**. Always obtain proper permission before scanning any target. The author is not responsible for misuse.

---

## License

MIT License — see LICENSE file for details.
