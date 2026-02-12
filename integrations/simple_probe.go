package integrations

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// SimpleProbeStep performs manual HTTP/HTTPS probing without external tools
// Replaces httpx with a pure Go implementation (XnovaX-style)
// Now with "Smart Scan" technology detection
type SimpleProbeStep struct {
	Runner *ToolRunner // Unused but kept for interface consistency
}

func (s *SimpleProbeStep) Name() string           { return "simple_probe" }
func (s *SimpleProbeStep) Description() string    { return "Manual HTTP/HTTPS probing to filter live hosts" }
func (s *SimpleProbeStep) Category() string       { return "recon" }
func (s *SimpleProbeStep) RequiredTools() []string { return []string{} }

func (s *SimpleProbeStep) Validate(config map[string]interface{}) error {
	return nil
}

func (s *SimpleProbeStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Collect hosts
	var hosts []string
	if targetsFrom, ok := config["targets_from"]; ok {
		// Handle single string
		if single, ok := targetsFrom.(string); ok {
			sHosts := ctx.GetHostsFromStep(single)
			if len(sHosts) == 0 {
				sHosts = ctx.GetURLsFromStep(single) // Fallback if step returned URLs
			}
			hosts = append(hosts, sHosts...)
		}
		// Handle list of strings
		if list, ok := targetsFrom.([]interface{}); ok {
			for _, item := range list {
				if stepName, ok := item.(string); ok {
					sHosts := ctx.GetHostsFromStep(stepName)
					if len(sHosts) == 0 {
						sHosts = ctx.GetURLsFromStep(stepName)
					}
					hosts = append(hosts, sHosts...)
				}
			}
		}
	}
	
	if len(hosts) == 0 {
		hosts = ctx.DiscoveredHosts.Items()
	}
	if len(hosts) == 0 {
		hosts = []string{ctx.TargetURL}
	}
	
	// Deduplicate
	hosts = core.Unique(hosts)

	stepResult := &pipeline.StepResult{
		Name: "simple_probe",
	}

	threads := getIntConfig(config, "threads", 50)
	timeout := getIntConfig(config, "timeout", 10) // Seconds per request

	ctx.Logger.Info("Probing %d hosts with %d threads (manual mode + tech detect)...", len(hosts), threads)

	// Worker pool setup
	jobs := make(chan string, len(hosts))
	results := make(chan core.Result, len(hosts))
	var wg sync.WaitGroup

	// Create evasion client (if configured)
	evasionConfig := core.EvasionConfig{
		Profile:           "chrome",
		RateLimit:         5,  // 5 req/s
		JitterMs:          500,
		RetryOn429:        true,
		RetryOn503:        true,
		MaxRetries:        3,
		BackoffFactor:     2,
		RespectRetryAfter: true,
		RandomTLSProfile:  true,
		Timeout:           time.Duration(timeout) * time.Second,
	}
	// Adjust rate limit based on thread count
	if threads > 50 {
		evasionConfig.RateLimit = 10
	}
	evasionClient, err := core.NewEvasionClient(evasionConfig)
	if err != nil {
		ctx.Logger.Warn("Failed to create evasion client, using standard: %v", err)
		evasionClient = nil
	}

	// Start workers
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			
			for host := range jobs {
				host = strings.TrimSpace(host)
				if host == "" {
					continue
				}

				// Try HTTPS first, then HTTP
				protocols := []string{"https://", "http://"}
				if strings.Contains(host, "://") {
					protocols = []string{""} // Already has protocol
				}

				for _, proto := range protocols {
					targetURL := proto + host
					if proto == "" {
						targetURL = host
					}

					// Use evasion client if available
					var resp *http.Response
					var err error
					if evasionClient != nil {
						resp, err = evasionClient.Get(ctx.Context, targetURL)
					} else {
						// Fallback to standard client
						client := &http.Client{
							Timeout: time.Duration(timeout) * time.Second,
							Transport: &http.Transport{
								TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
								MaxIdleConns:    100,
								MaxIdleConnsPerHost: 10,
							},
						}
						resp, err = client.Get(targetURL)
					}
					
					if err != nil {
						continue
					}
					
					// Read body
					bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 16384)) // Read 16KB
					bodyStr := string(bodyBytes)
					title := extractTitle(bodyStr)
					resp.Body.Close()

					// Visual Output (Real-time) - Tech detection now handled by TechFinder step
					if resp.StatusCode < 400 {
						ctx.Logger.Success("%s [%d] %s", targetURL, resp.StatusCode, title)
					}

					// Record Live Host
					res := core.Result{
						Type:       "live-host",
						URL:        targetURL,
						Source:     "simple_probe",
						StatusCode: resp.StatusCode,
						Evidence:   fmt.Sprintf("[%d] %s", resp.StatusCode, title),
					}
					results <- res
					
					// If we get a valid response (even 403), consider it live and move to next host
					// Don't try HTTP if HTTPS worked
					break
				}
			}
		}()
	}

	// Submit jobs
	for _, host := range hosts {
		jobs <- host
	}
	close(jobs)

	// Wait for workers in background then close results
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	count := 0
	techSet := make(map[string]bool)
	for res := range results {
		stepResult.Results = append(stepResult.Results, res)
		if res.Type == "live-host" {
			// Only valid/useful hosts (2xx, 3xx) go to next steps
			if res.StatusCode < 400 {
				count++
				stepResult.URLs = append(stepResult.URLs, res.URL)
				stepResult.Hosts = append(stepResult.Hosts, res.URL)
			}
		}
		if res.Type == "technology" {
			techSet[res.Value] = true
		}
	}

	// Summarize techs
	var techList []string
	for t := range techSet {
		techList = append(techList, t)
	}
	ctx.Logger.Success("Probe complete: %d live hosts. Techs found: %v", count, techList)
	
	return stepResult, nil
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	if end-start > 200 {
		return strings.TrimSpace(body[start : start+200]) + "..."
	}
	return strings.TrimSpace(body[start : start+end])
}

// detectTechnologies checks headers and body for common signatures
func detectTechnologies(headers http.Header, body string) []string {
	var techs []string
	
	// Check Headers
	server := headers.Get("Server")
	poweredBy := headers.Get("X-Powered-By")
	
	if strings.Contains(strings.ToLower(server), "apache") {
		techs = append(techs, "apache")
	}
	if strings.Contains(strings.ToLower(server), "nginx") {
		techs = append(techs, "nginx")
	}
	if strings.Contains(strings.ToLower(server), "iis") || strings.Contains(strings.ToLower(poweredBy), "asp.net") {
		techs = append(techs, "iis", "aspnet")
	}
	if strings.Contains(strings.ToLower(poweredBy), "php") {
		techs = append(techs, "php")
	}
	
	// Check Body (simple signatures)
	lowerBody := strings.ToLower(body)
	if strings.Contains(lowerBody, "wp-content") || strings.Contains(lowerBody, "wp-includes") {
		techs = append(techs, "wordpress")
	}
	if strings.Contains(lowerBody, "drupal") {
		techs = append(techs, "drupal")
	}
	if strings.Contains(lowerBody, "joomla") {
		techs = append(techs, "joomla")
	}
	if strings.Contains(lowerBody, "laravel") {
		techs = append(techs, "laravel")
	}
	if strings.Contains(lowerBody, "django") {
		techs = append(techs, "django")
	}

	return uniqueStrings(techs)
}

func uniqueStrings(input []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range input {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}
