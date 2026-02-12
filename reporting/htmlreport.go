package reporting

import (
	"fmt"
	"html/template"
	"os"
	"time"

	"github.com/veex0x01/ultrafinder/core"
)

// ScanStats holds aggregated scan statistics
type ScanStats struct {
	TotalURLs       int            `json:"total_urls"`
	TotalParams     int            `json:"total_params"`
	TotalForms      int            `json:"total_forms"`
	TotalJS         int            `json:"total_js"`
	TotalSubdomains int            `json:"total_subdomains"`
	TotalVulns      int            `json:"total_vulns"`
	BySeverity      map[string]int `json:"by_severity"`
	ByType          map[string]int `json:"by_type"`
	ByTool          map[string]int `json:"by_tool"`
}

// NewScanStats creates initialized ScanStats
func NewScanStats() ScanStats {
	return ScanStats{
		BySeverity: make(map[string]int),
		ByType:     make(map[string]int),
		ByTool:     make(map[string]int),
	}
}

// HTMLReport generates an HTML scan report
type HTMLReport struct {
	Title     string
	Target    string
	StartTime time.Time
	EndTime   time.Time
	Results   []core.Result
	Stats     ScanStats
}

// ComputeStats calculates stats from results
func (r *HTMLReport) ComputeStats() {
	r.Stats = NewScanStats()
	for _, result := range r.Results {
		r.Stats.ByType[result.Type]++
		if result.Severity != "" {
			r.Stats.BySeverity[result.Severity]++
		}
		if result.Tool != "" {
			r.Stats.ByTool[result.Tool]++
		}
		switch result.Type {
		case "url", "href":
			r.Stats.TotalURLs++
		case "sensitive-param", "hidden-field":
			r.Stats.TotalParams++
		case "form", "upload-form":
			r.Stats.TotalForms++
		case "js", "javascript", "linkfinder":
			r.Stats.TotalJS++
		case "subdomain":
			r.Stats.TotalSubdomains++
		case "sqli", "xss", "lfi", "rce", "ssrf", "idor", "privesc", "auth-bypass", "cve":
			r.Stats.TotalVulns++
		}
	}
}

// Generate creates the HTML report file
func (r *HTMLReport) Generate(outputPath string) error {
	r.ComputeStats()

	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse template: %w", err)
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, r)
}

const reportTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{.Title}}</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',system-ui,sans-serif;padding:20px}
.header{background:linear-gradient(135deg,#161b22,#1f2937);padding:30px;border-radius:12px;margin-bottom:24px;border:1px solid #30363d}
.header h1{color:#58a6ff;font-size:28px;margin-bottom:8px}
.header p{color:#8b949e;font-size:14px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;text-align:center}
.stat-card .value{font-size:32px;font-weight:700;color:#58a6ff}
.stat-card .label{font-size:13px;color:#8b949e;margin-top:4px}
.section{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px;margin-bottom:16px}
.section h2{color:#58a6ff;margin-bottom:16px;font-size:20px}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px;border-bottom:2px solid #30363d;color:#8b949e;font-size:13px;text-transform:uppercase}
td{padding:10px;border-bottom:1px solid #21262d;font-size:14px}
tr:hover{background:#1c2128}
.severity{padding:3px 8px;border-radius:4px;font-size:12px;font-weight:600}
.sev-CRITICAL{background:#f8514940;color:#f85149}
.sev-HIGH{background:#da363340;color:#da3633}
.sev-MEDIUM{background:#d2960040;color:#d29600}
.sev-LOW{background:#58a6ff40;color:#58a6ff}
.sev-INFO{background:#8b949e40;color:#8b949e}
.footer{text-align:center;color:#484f58;font-size:12px;margin-top:24px;padding:16px}
</style>
</head>
<body>
<div class="header">
<h1>🔍 {{.Title}}</h1>
<p>Target: {{.Target}} | Scan Duration: {{.EndTime.Sub .StartTime}} | Generated: {{.EndTime.Format "2006-01-02 15:04:05 UTC"}}</p>
</div>
<div class="stats-grid">
<div class="stat-card"><div class="value">{{.Stats.TotalURLs}}</div><div class="label">URLs Discovered</div></div>
<div class="stat-card"><div class="value">{{.Stats.TotalParams}}</div><div class="label">Parameters Found</div></div>
<div class="stat-card"><div class="value">{{.Stats.TotalVulns}}</div><div class="label">Vulnerabilities</div></div>
<div class="stat-card"><div class="value">{{.Stats.TotalJS}}</div><div class="label">JS Files</div></div>
<div class="stat-card"><div class="value">{{.Stats.TotalSubdomains}}</div><div class="label">Subdomains</div></div>
<div class="stat-card"><div class="value">{{len .Results}}</div><div class="label">Total Findings</div></div>
</div>
<div class="section">
<h2>📊 Findings</h2>
<table>
<thead><tr><th>Type</th><th>URL</th><th>Details</th><th>Severity</th><th>Source</th></tr></thead>
<tbody>
{{range .Results}}
<tr>
<td>{{.Type}}</td>
<td style="word-break:break-all;max-width:400px">{{.URL}}</td>
<td>{{if .Parameter}}{{.Parameter}}={{.Value}}{{else if .Evidence}}{{.Evidence}}{{end}}</td>
<td>{{if .Severity}}<span class="severity sev-{{.Severity}}">{{.Severity}}</span>{{else}}-{{end}}</td>
<td>{{if .Tool}}{{.Tool}}{{else}}{{.Source}}{{end}}</td>
</tr>
{{end}}
</tbody>
</table>
</div>
<div class="footer">Generated by UltraFinder v2.0 — veex0x01</div>
</body>
</html>`
