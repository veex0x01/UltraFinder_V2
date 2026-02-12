package authscan

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/reporting"
)

// AuthBypassScanner tests for missing authentication checks
type AuthBypassScanner struct {
	sessions *SessionManager
	output   *core.Output
	logger   *reporting.Logger
}

// NewAuthBypassScanner creates a new auth bypass scanner
func NewAuthBypassScanner(sessions *SessionManager, output *core.Output, logger *reporting.Logger) *AuthBypassScanner {
	return &AuthBypassScanner{
		sessions: sessions,
		output:   output,
		logger:   logger,
	}
}

// BypassTechniques to try
var BypassTechniques = []struct {
	Name    string
	Headers map[string]string
}{
	{"X-Forwarded-For localhost", map[string]string{"X-Forwarded-For": "127.0.0.1"}},
	{"X-Original-URL", map[string]string{"X-Original-URL": "/admin"}},
	{"X-Rewrite-URL", map[string]string{"X-Rewrite-URL": "/admin"}},
	{"X-Custom-IP-Authorization", map[string]string{"X-Custom-IP-Authorization": "127.0.0.1"}},
	{"X-Forwarded-Host", map[string]string{"X-Forwarded-Host": "localhost"}},
	{"X-Host", map[string]string{"X-Host": "localhost"}},
	{"X-Real-IP", map[string]string{"X-Real-IP": "127.0.0.1"}},
}

// PathBypassPatterns are URL path manipulations to try
var PathBypassPatterns = []string{
	"%s/",
	"%s/.",
	"//%s",
	"%s/..",
	"%s;/",
	"%s/.;/",
	"%s/..;/",
	"%s%%20",
	"%s%%09",
	"%s%%00",
	"%s..%3B/",
	"%s#",
	"%s?",
}

// TestEndpoint tests an endpoint for authentication bypass
func (a *AuthBypassScanner) TestEndpoint(endpoint string) []core.Result {
	var results []core.Result

	// First verify endpoint requires auth (returns 401/403)
	resp, err := a.sessions.SendUnauthenticated("GET", endpoint)
	if err != nil {
		return results
	}
	if resp.StatusCode != 401 && resp.StatusCode != 403 {
		return results // Endpoint doesn't seem to require auth
	}

	// Test header-based bypasses
	for _, technique := range BypassTechniques {
		result := a.tryBypassWithHeaders(endpoint, technique.Name, technique.Headers)
		if result != nil {
			results = append(results, *result)
		}
	}

	// Test path-based bypasses
	for _, pattern := range PathBypassPatterns {
		modifiedURL := fmt.Sprintf(pattern, endpoint)
		resp, err := a.sessions.SendUnauthenticated("GET", modifiedURL)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 {
			results = append(results, core.Result{
				Type:     "auth-bypass",
				URL:      modifiedURL,
				Source:   "auth-bypass-scanner",
				Tool:     "auth-bypass-scanner",
				Severity: "CRITICAL",
				Evidence: fmt.Sprintf("Path manipulation bypassed auth: %s → %d", modifiedURL, resp.StatusCode),
			})
		}
	}

	return results
}

func (a *AuthBypassScanner) tryBypassWithHeaders(endpoint, techniqueName string, headers map[string]string) *core.Result {
	req, err := newHTTPRequest("GET", endpoint)
	if err != nil {
		return nil
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := a.sessions.client.Do(req)
	if err != nil {
		return nil
	}

	if resp.StatusCode == 200 {
		return &core.Result{
			Type:      "auth-bypass",
			URL:       endpoint,
			Source:    "auth-bypass-scanner",
			Tool:      "auth-bypass-scanner",
			Parameter: techniqueName,
			Severity:  "CRITICAL",
			Evidence:  fmt.Sprintf("Header bypass '%s' returned status %d", techniqueName, resp.StatusCode),
		}
	}

	return nil
}

// ScanURLs tests a list of URLs for auth bypass
func (a *AuthBypassScanner) ScanURLs(urls []string) []core.Result {
	var results []core.Result

	for _, u := range urls {
		// Only test URLs that look like they might require auth
		lowerURL := strings.ToLower(u)
		interesting := false
		for _, keyword := range []string{"/admin", "/api", "/dashboard", "/manage", "/config", "/internal", "/panel"} {
			if strings.Contains(lowerURL, keyword) {
				interesting = true
				break
			}
		}
		if !interesting {
			continue
		}

		urlResults := a.TestEndpoint(u)
		results = append(results, urlResults...)
	}

	return results
}

func newHTTPRequest(method, url string) (*http.Request, error) {
	return http.NewRequest(method, url, nil)
}
