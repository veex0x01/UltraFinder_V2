package integrations

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"os"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// ShodanStep queries Shodan's free API for CVEs and service information
type ShodanStep struct {
	Runner *ToolRunner
}

func (s *ShodanStep) Name() string           { return "shodan" }
func (s *ShodanStep) Description() string    { return "Query Shodan for CVEs and service info (free API)" }
func (s *ShodanStep) Category() string       { return "recon" }
func (s *ShodanStep) RequiredTools() []string { return []string{} }

func (s *ShodanStep) Validate(config map[string]interface{}) error {
	return nil
}

func (s *ShodanStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Extract domain from target
	domain := resolveDomain(ctx.TargetURL, config)
	
	ctx.Logger.Info("Querying Shodan for %s (using free InternetDB API)...", domain)
	
	stepResult := &pipeline.StepResult{
		Name: "shodan",
	}
	
	// Use Shodan's free InternetDB API (no API key needed)
	// https://internetdb.shodan.io/{ip}
	
	// First, resolve domain to IP (basic DNS lookup)
	// For simplicity, we'll query domain directly if it's an IP
	// Otherwise, use a simple approach
	
	// Query InternetDB
	resp, err := http.Get(fmt.Sprintf("https://internetdb.shodan.io/%s", domain))
	if err != nil {
		ctx.Logger.Warn("Shodan query failed: %v", err)
		return stepResult, nil // Don't fail pipeline
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		ctx.Logger.Warn("Shodan returned %d - target may not be indexed", resp.StatusCode)
		return stepResult, nil
	}
	
	body, _ := io.ReadAll(resp.Body)
	
	var shodanData ShodanInternetDB
	if err := json.Unmarshal(body, &shodanData); err != nil {
		ctx.Logger.Warn("Failed to parse Shodan data: %v", err)
		return stepResult, nil
	}
	
	ctx.Logger.Success("Shodan: Found %d CVEs, %d ports, %d tags", 
		len(shodanData.Vulns), len(shodanData.Ports), len(shodanData.Tags))
	
	// Store and display CVEs
	if len(shodanData.Vulns) > 0 {
		ctx.Logger.Success("🎯 Shodan found %d CVEs:", len(shodanData.Vulns))
	}
	for _, cve := range shodanData.Vulns {
		ctx.Logger.Success("  → %s", cve)
		result := core.Result{
			Type:     "cve",
			Value:    cve,
			Source:   "shodan",
			URL:      ctx.TargetURL,
			Evidence: fmt.Sprintf("Shodan InternetDB: %s", cve),
		}
		stepResult.Results = append(stepResult.Results, result)
	}
	
	// Store service/technology info
	for _, tag := range shodanData.Tags {
		result := core.Result{
			Type:   "technology",
			Value:  tag,
			Source: "shodan",
			URL:    ctx.TargetURL,
		}
		stepResult.Results = append(stepResult.Results, result)
	}
	
	// Store open ports
	for _, port := range shodanData.Ports {
		result := core.Result{
			Type:     "port",
			Value:    fmt.Sprintf("%d", port),
			Source:   "shodan",
			URL:      ctx.TargetURL,
			Evidence: fmt.Sprintf("Open port: %d", port),
		}
		stepResult.Results = append(stepResult.Results, result)
	}
	
	return stepResult, nil
}

// ShodanInternetDB represents the free Shodan InternetDB response
type ShodanInternetDB struct {
	IP       string   `json:"ip"`
	Ports    []int    `json:"ports"`
	CPEs     []string `json:"cpes"`
	Vulns    []string `json:"vulns"` // CVE IDs
	Tags     []string `json:"tags"`  // Technologies/services
	Hostnames []string `json:"hostnames"`
}

// SmartNucleiStep runs Nuclei with intelligent template selection
type SmartNucleiStep struct {
	Runner *ToolRunner
}

func (sn *SmartNucleiStep) Name() string           { return "smart_nuclei" }
func (sn *SmartNucleiStep) Description() string    { return "Intelligent Nuclei scanning with minimal templates" }
func (sn *SmartNucleiStep) Category() string       { return "vuln" }
func (sn *SmartNucleiStep) RequiredTools() []string { return []string{"nuclei"} }

func (sn *SmartNucleiStep) Validate(config map[string]interface{}) error {
	return nil
}

func (sn *SmartNucleiStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Collect URLs
	var urls []string
	if targetsFrom, ok := config["targets_from"].(string); ok {
		urls = ctx.GetURLsFromStep(targetsFrom)
	}
	if len(urls) == 0 {
		urls = []string{ctx.TargetURL}
	}
	
	// Gather intelligence from previous steps
	var detectedTechs []string
	var detectedCVEs []string
	
	// Get techs from tech detection
	if techFrom, ok := config["technologies_from"].(string); ok {
		results := ctx.GetResultsFromStep(techFrom)
		techSet := make(map[string]bool)
		for _, r := range results {
			if r.Type == "technology" {
				tech := strings.ToLower(r.Value)
				if !techSet[tech] {
					detectedTechs = append(detectedTechs, tech)
					techSet[tech] = true
				}
			}
		}
	}
	
	// Get CVEs from Shodan
	if cveFrom, ok := config["cve_from"].(string); ok {
		results := ctx.GetResultsFromStep(cveFrom)
		for _, r := range results {
			if r.Type == "cve" {
				detectedCVEs = append(detectedCVEs, r.Value)
			}
		}
	}
	
	ctx.Logger.Info("Smart Nuclei: %d techs, %d CVEs detected", len(detectedTechs), len(detectedCVEs))
	if len(detectedTechs) > 0 {
		ctx.Logger.Info("Technologies: %v", detectedTechs)
	}
	
	
	// Build smart template selection
	var templates []string
	
	// 1. CVE-specific templates (HIGHEST PRIORITY)
	if len(detectedCVEs) > 0 {
		ctx.Logger.Success("Targeting %d specific CVEs from Shodan", len(detectedCVEs))
		for _, cve := range detectedCVEs {
			// Nuclei has CVE templates named like: cves/2021/CVE-2021-12345.yaml
			templates = append(templates, fmt.Sprintf("cves/%s", cve))
		}
	}
	
	// 2. Technology-specific templates (MEDIUM PRIORITY)
	// Use latest 2025-2026 templates for detected technologies
	if len(detectedTechs) > 0 {
		ctx.Logger.Success("Detected %d technologies - using latest templates", len(detectedTechs))
		techTemplates := mapTechsToTemplates(detectedTechs)
		templates = append(templates, techTemplates...)
		if len(techTemplates) > 0 {
			ctx.Logger.Info("Added %d tech-specific templates", len(techTemplates))
		}
	}
	
	
	// Write target URLs to file
	urlFile, err := WriteURLListToTempFile(urls)
	if err != nil {
		return nil, err
	}
	defer os.Remove(urlFile)
	
	// Build Nuclei args (LOW-NOISE OPTIMIZED)
	args := []string{
		"-l", urlFile,
		"-jsonl",
		"-stats",
		"-v",
		"-nc",
		"-severity", "high,critical",  // High/Critical only for stealth
		"-c", "5",                      // Concurrency: 5
		"-rl", "5",                     // Rate limit: 5 req/s
		"-timeout", "10",               // Timeout: 10s
		"-retries", "1",                // Retries: 1 only
	}
	
	// Only add specific CVE templates if found
	templateCount := 0
	for _, tmpl := range templates {
		args = append(args, "-t", tmpl)
		templateCount++
	}
	
	// Only skip if we have absolutely nothing to scan
	if templateCount == 0 {
		ctx.Logger.Warn("No CVEs or tech-specific templates - skipping Nuclei")
		return &pipeline.StepResult{Name: "smart_nuclei"}, nil
	}
	
	ctx.Logger.Info("Running Nuclei with %d templates (low-noise mode: c=5, rl=5)", templateCount)
	
	result, err := sn.Runner.Run(ctx.Context, RunConfig{
		Name:         "smart_nuclei",
		Binary:       "nuclei",
		Args:         args,
		Timeout:      20 * time.Minute,
		StreamOutput: true,
	})
	if err != nil {
		return nil, err
	}
	
	return parseNucleiOutput(result.Stdout)
}

// parseNucleiOutput parses Nuclei JSONL output
func parseNucleiOutput(data []byte) (*pipeline.StepResult, error) {
	stepResult := &pipeline.StepResult{
		Name: "smart_nuclei",
	}
	
	lines := parseLines(data)
	for _, line := range lines {
		var nr NucleiResult
		if err := json.Unmarshal([]byte(line), &nr); err != nil {
			continue
		}
		
		severity := nr.Info.Severity
		if severity == "" {
			severity = "INFO"
		}
		
		result := core.Result{
			Type:     "vulnerability",
			URL:      nr.MatchedAt,
			Source:   "nuclei",
			Tool:     "nuclei",
			Severity: mapNucleiSeverity(severity),
			Evidence: nr.Info.Description,
			Value:    nr.Info.Name,
		}
		
		if nr.TemplateID != "" {
			result.Parameter = nr.TemplateID
		}
		
		stepResult.Results = append(stepResult.Results, result)
		if nr.MatchedAt != "" {
			stepResult.URLs = append(stepResult.URLs, nr.MatchedAt)
		}
	}
	
	return stepResult, nil
}

// NucleiResult represents Nuclei JSONL output
type NucleiResult struct {
	TemplateID string `json:"template-id"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Type       string `json:"type"`
	Info       struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
}

// mapTechsToTemplates maps detected technologies to latest Nuclei template paths (2025-2026)
func mapTechsToTemplates(techs []string) []string {
	var templates []string
	
	// Technology to template mapping - focusing on popular and high-value targets
	techMap := map[string][]string{
		// CMS
		"wordpress": {
			"http/cves/2024/",
			"http/vulnerabilities/wordpress/",
			"http/misconfiguration/wordpress/",
		},
		"joomla": {
			"http/cves/2024/",
			"http/vulnerabilities/joomla/",
		},
		"drupal": {
			"http/cves/2024/",
			"http/vulnerabilities/drupal/",
		},
		
		// Programming Languages & Frameworks
		"php": {
			"http/vulnerabilities/other/",
		},
		"laravel": {
			"http/vulnerabilities/laravel/",
		},
		
		// Web Servers
		"nginx": {
			"http/cves/2024/",
			"http/misconfiguration/", // Broad but safer than invalid path
		},
		"apache": {
			"http/vulnerabilities/apache/",
			"http/misconfiguration/apache/",
		},
		
		// Databases
		"mysql": {
			"http/exposed-panels/", // Look for phpMyAdmin etc
		},
		"mongodb": {
			"http/misconfiguration/mongodb/",
		},
		
		// Cloud
		"amazon s3": {
			"http/misconfiguration/s3/",
		},
		
		// General
		"python": {
			"http/cves/2024/",
		},
	}
	
	// Check each detected technology
	for _, tech := range techs {
		tech = strings.ToLower(tech)
		
		// Direct match
		if tmpls, ok := techMap[tech]; ok {
			templates = append(templates, tmpls...)
		}
		
		// Keyword match (e.g. "nginx/1.2" matches "nginx")
		for key, tmpls := range techMap {
			if strings.Contains(tech, key) {
				templates = append(templates, tmpls...)
			}
		}
	}
	
	// Remove duplicates
	seen := make(map[string]bool)
	var unique []string
	for _, t := range templates {
		if !seen[t] {
			seen[t] = true
			unique = append(unique, t)
		}
	}
	
	return unique
}
