# UltraFinder

```
   __  ______             _______           __
  / / / / / /__________ _/ ____(_)___  ____/ /__  _____
 / / / / / __/ ___/ __ '/ /_  / / __ \/ __  / _ \/ ___/
/ /_/ / / /_/ /  / /_/ / __/ / / / / / /_/ /  __/ /
\____/_/\__/_/   \__,_/_/   /_/_/ /_/\__,_/\___/_/
```

**Advanced Web Reconnaissance Tool**

UltraFinder is a fast, comprehensive web reconnaissance tool built in Go. Designed for security professionals who need efficient endpoint discovery, parameter analysis, and deep content inspection.

**Thanks for [hacker1337](https://github.com/hacker1337itme) for making this tool looks better**

![Screenshot](s2.png)

---

## Features

**Core Capabilities**

- Fast async web crawling with configurable depth and concurrency
- JavaScript endpoint extraction from JS files
- Sensitive parameter detection in URLs and forms
- Hidden form field discovery
- Subdomain extraction from response bodies
- AWS S3 bucket detection

**Smart Recon & Vulnerability Hunting (NEW)**

- **TechFinder Integration**: Advanced technology detection (CMS, Frameworks, Servers) using Headless Chrome.
- **SmartNuclei**: Intelligent vulnerability scanning that maps detected technologies to specific CVE templates (e.g., WordPress -> WP CVEs, Nginx -> Nginx Misconfigs).
- **Stealth Pipeline**: Optimized for low-noise scanning with randomized delays and smart skipping.
- **Shodan Integration**: Automatically fetches CVEs from Shodan InternetDB.

**External Sources**

- Wayback Machine integration
- CommonCrawl data fetching
- AlienVault OTX threat intelligence

**Stealth Mode**

- Random User-Agent rotation
- Request delay randomization
- Browser-like header simulation

**Deep Analysis**

- API key and secret detection (AWS, GitHub, Slack, Stripe, JWT)
- AJAX/XHR endpoint parsing
- WAF/CDN detection (Cloudflare, AWS WAF, Akamai, Imperva)
- Backup file discovery
- Source map parsing

---

## Installation

```bash
git clone https://github.com/veex0x01/UltraFinder.git
cd UltraFinder
go mod tidy
go build -o ultrafinder .
```

You also need the **TechFinder** binary in the `techFinder/` directory and **Nuclei** installed.

---

## Usage

**Basic Scan**

```bash
./ultrafinder -u https://target.com
```

**🚀 Smart Recon + CVE Hunt (Recommended)**
This runs the full pipeline: Live Probe -> Tech Detection -> Shodan -> SmartNuclei -> Crawl.

```bash
./ultrafinder pipeline -f configs/smart_hunt.yaml -t target.com --scope exact
```

**Full Manual Reconnaissance**

```bash
./ultrafinder -u https://target.com -d 3 -t 20 --stealth --deep --all-sources --subs -o results.txt
```

**With proxy (Burp Suite)**

```bash
./ultrafinder -u https://target.com -p http://127.0.0.1:8080
```

**JSON output**

```bash
./ultrafinder -u https://target.com --deep -o results.json --json
```

---

## Smart Hunt Pipeline

The `configs/smart_hunt.yaml` pipeline orchestrates a sophisticated attack surface reduction workflow:

1. **Live Filter**: Probes hosts to find live endpoints.
2. **Tech Detection**: Uses **TechFinder** (Chrome-based) to identify stack (WordPress, PHP, Jira, etc.).
3. **Shodan CVEs**: Queries Shodan for known open ports and CVEs.
4. **SmartNuclei**:
   - Takes technologies from Step 2.
   - Selects *only* relevant Nuclei templates (e.g., if "Jira" found, runs Jira CVEs).
   - Skips scanning if no relevant techs/CVEs found (Stealth Mode).
5. **Crawl**: Deep crawling for parameters and endpoints.

---

## Options

| Flag                 | Description                       | Default |
| -------------------- | --------------------------------- | ------- |
| `-u, --url`        | Target URL (required)             | -       |
| `pipeline`         | Run a workflow pipeline           | -       |
| `-f, --file`       | Pipeline config file              | -       |
| `-t, --target`     | Pipeline target                   | -       |
| `--scope`          | Pipeline scope (exact/subdomains) | exact   |
| `-d, --depth`      | Maximum crawl depth               | 2       |
| `-t, --threads`    | Concurrent threads                | 10      |
| `-m, --timeout`    | Request timeout (seconds)         | 30      |
| `-k, --delay`      | Delay between requests (seconds)  | 0       |
| `--random-delay`   | Random delay jitter (ms)          | 0       |
| `-p, --proxy`      | Proxy URL                         | -       |
| `-c, --cookie`     | Cookie string                     | -       |
| `-H, --header`     | Custom header (repeatable)        | -       |
| `-a, --user-agent` | Custom User-Agent                 | -       |
| `--no-redirect`    | Disable redirects                 | false   |
| `--stealth`        | Enable stealth mode               | false   |
| `--random-ua`      | Random User-Agent per request     | false   |
| `--deep`           | Enable deep analysis              | false   |
| `--subs`           | Include subdomains                | false   |
| `--wayback`        | Fetch from Wayback Machine        | false   |
| `--commoncrawl`    | Fetch from CommonCrawl            | false   |
| `--otx`            | Fetch from AlienVault OTX         | false   |
| `--all-sources`    | Fetch from all sources            | false   |
| `-o, --output`     | Output file path                  | -       |
| `--json`           | JSON output format                | false   |
| `-v, --verbose`    | Verbose output                    | false   |
| `-q, --quiet`      | Suppress console output           | false   |

---

## Output Types

| Type                  | Description                              |
| --------------------- | ---------------------------------------- |
| `[technology]`      | Detected Tech (CMS, Server, Lang)        |
| `[cve]`             | Detected Vulnerabilities (Shodan/Nuclei) |
| `[href]`            | HTML links                               |
| `[form]`            | Form actions                             |
| `[js]`              | JavaScript files                         |
| `[linkfinder]`      | URLs from JS                             |
| `[sensitive-param]` | Sensitive parameters                     |
| `[hidden-field]`    | Hidden form fields                       |
| `[api-key]`         | Detected secrets                         |
| `[ajax-endpoint]`   | AJAX endpoints                           |
| `[waf-detected]`    | WAF/CDN info                             |
| `[backup-probe]`    | Backup files                             |
| `[subdomain]`       | Subdomains                               |
| `[aws-s3]`          | S3 buckets                               |

---

## 📚 Cheat Sheet & Service Guide

Here is a quick reference for running each service, what it needs, and what it produces.

### 1. 🚀 Full Smart Hunt (Recommended)

**What it does**: Runs the entire pipeline: Live Filter -> Tech Detection -> Shodan -> SmartNuclei -> Crawl.
**Input**: A target domain (e.g., `example.com`).
**Output**: Full vulnerability report + technologies + crawled endpoints.

```bash
# Run on exact domain
./ultrafinder pipeline -f configs/smart_hunt.yaml -t example.com --scope exact

# Run on subdomains (if you have a list)
./ultrafinder pipeline -f configs/smart_hunt.yaml -t example.com --scope subdomains
```

---

### 2. 🕵️ Tech Detection (TechFinder)

**What it does**: Uses Headless Chrome to detect CMS, frameworks, servers, and plugins.
**Input**: URL or file with URLs.
**Output**: JSON list of technologies with confidence scores.

**Command:**

```bash
# Single URL
./techFinder/techfinder https://example.com -p

# With timeout and specific user agent
./techFinder/techfinder https://example.com -p -w 90000 -a "Mozilla/5.0"
```

**Example Output:**

```json
{
  "technologies": [
    { "name": "WordPress", "version": "6.4.2", "confidence": 100 },
    { "name": "MySQL", "confidence": 100 }
  ]
}
```

---

### 3. ☢️ Vulnerability Scan (SmartNuclei)

**What it does**: Scans for CVEs *specific* to the technologies found (e.g., if WordPress is found, runs only WP templates).
**Input**: Target URL + List of Technologies.
**Output**: Confirmed vulnerabilities (CVEs).

**Command (Standalone):**

```bash
# Run Nuclei directly if needed
nuclei -u https://example.com -t http/cves/2024/ -t http/vulnerabilities/wordpress/
```

*(Note: UltraFinder automates this selection for you in the pipeline)*

---

### 4. 🕷️ Deep Crawler

**What it does**: Crawls the site to find parameters, hidden fields, and endpoints.
**Input**: Seed URL.
**Output**: List of URLs, parameters, and secrets.

**Command:**

```bash
# basic crawl (depth 2)
./ultrafinder -u https://example.com -d 2

# deep stealth crawl (depth 3, random delay)
./ultrafinder -u https://example.com -d 3 -t 20 --stealth --deep
```

---

### 5. 🔍 Shodan CVEs

**What it does**: Queries Shodan InternetDB for open ports and known CVEs.
**Input**: Domain / IP.
**Output**: List of CVE IDs and Ports.

**Command:**
*(Integrated automatically in the pipeline)*

---

## 🌐 Web UI (Mission Control)

UltraFinder v2.0 includes a professional "Red Team" Dashboard for advanced operation management.

### **Launch**
```bash
./ultrafinder webui -l :8080
```
Access via **`http://localhost:8080`**.

### **Features**
*   **Mission Control**: Configure scans with toggles for **Stealth**, **Deep Crawl**, **Tech Detect**, and **Smart Nuclei**.
*   **Live Terminal**: Watch scan logs stream in real-time with hacker-style aesthetics.
*   **Intelligence Report**: View and filter all discovered assets and vulnerabilities.
*   **Operation History**: Track and review past missions.

> **Note**: The UI is designed to be "stable and aggressive" with a dark Red/Black theme.

---

## 📂 Output Files

Results are saved in `results/<target>/`:

- `results.json`: Full structured data.
- `crawled_urls.txt`: All discovered URLs.
- `params.txt`: Unique parameters found.
- `secrets.txt`: API keys and secrets found.
- `vulnerabilities.txt`: Nuclei & Shodan findings.

---

## Sponsor

If you find this tool useful, consider supporting development:

[Support via PayPal](https://www.paypal.com/ncp/payment/BNSJG52TFE5B2)

---

## Disclaimer

This tool is for authorized security testing only. Always obtain proper permission before scanning any target. The author is not responsible for misuse.

---

## License

MIT License - see LICENSE file for details.

---

**Author:** veex0x01
