package authscan

import (
	"fmt"
	"strings"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/reporting"
)

// PrivEscScanner tests for privilege escalation vulnerabilities
type PrivEscScanner struct {
	sessions   *SessionManager
	output     *core.Output
	logger     *reporting.Logger
}

// NewPrivEscScanner creates a new privilege escalation scanner
func NewPrivEscScanner(sessions *SessionManager, output *core.Output, logger *reporting.Logger) *PrivEscScanner {
	return &PrivEscScanner{
		sessions: sessions,
		output:   output,
		logger:   logger,
	}
}

// AdminPaths are common admin-only endpoints to test
var AdminPaths = []string{
	"/admin", "/admin/", "/admin/dashboard",
	"/api/admin", "/api/users", "/api/settings",
	"/manage", "/management", "/panel",
	"/dashboard", "/internal", "/config",
	"/api/admin/users", "/api/admin/config",
}

// TestEndpoint checks if a low-priv session can access a high-priv endpoint
func (p *PrivEscScanner) TestEndpoint(endpoint, adminSession, userSession string) []core.Result {
	var results []core.Result

	// Verify endpoint returns 200 for admin
	adminResp, err := p.sessions.SendRequest("GET", endpoint, adminSession, nil)
	if err != nil || adminResp.StatusCode != 200 {
		return results
	}
	adminBody := readBody(adminResp)

	// Try with user session
	userResp, err := p.sessions.SendRequest("GET", endpoint, userSession, nil)
	if err != nil {
		return results
	}
	userBody := readBody(userResp)

	// If user gets 200 with similar content → Privilege Escalation
	if userResp.StatusCode == 200 {
		similarity := calculateSimilarity(adminBody, userBody)
		if similarity > 0.5 {
			results = append(results, core.Result{
				Type:     "privesc",
				URL:      endpoint,
				Source:   "privesc-scanner",
				Tool:     "privesc-scanner",
				Severity: "CRITICAL",
				Evidence: fmt.Sprintf("User '%s' can access admin endpoint (%.0f%% similar, status %d)",
					userSession, similarity*100, userResp.StatusCode),
			})
		}
	}

	// Try HTTP method tampering
	methods := []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	for _, method := range methods {
		resp, err := p.sessions.SendRequest(method, endpoint, userSession, nil)
		if err != nil {
			continue
		}
		if resp.StatusCode == 200 || resp.StatusCode == 201 || resp.StatusCode == 204 {
			results = append(results, core.Result{
				Type:      "privesc",
				URL:       endpoint,
				Source:    "privesc-scanner",
				Tool:      "privesc-scanner",
				Parameter: method,
				Severity:  "HIGH",
				Evidence:  fmt.Sprintf("Method tampering: %s returned %d for low-priv user", method, resp.StatusCode),
			})
		}
	}

	return results
}

// ScanAllPaths tests all known admin paths at a base URL
func (p *PrivEscScanner) ScanAllPaths(baseURL, adminSession, userSession string) []core.Result {
	var results []core.Result

	baseURL = strings.TrimRight(baseURL, "/")

	for _, path := range AdminPaths {
		endpoint := baseURL + path
		pathResults := p.TestEndpoint(endpoint, adminSession, userSession)
		results = append(results, pathResults...)
	}

	return results
}
