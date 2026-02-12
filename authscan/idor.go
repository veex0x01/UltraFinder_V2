package authscan

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/reporting"
)

// IDORScanner tests endpoints for Insecure Direct Object Reference vulnerabilities
type IDORScanner struct {
	sessions *SessionManager
	output   *core.Output
	logger   *reporting.Logger
}

// IDPattern represents a URL with an incrementable ID
type IDPattern struct {
	URL       string
	ParamName string
	ParamValue string
	IsPath    bool // ID in path vs query param
}

// NewIDORScanner creates a new IDOR scanner
func NewIDORScanner(sessions *SessionManager, output *core.Output, logger *reporting.Logger) *IDORScanner {
	return &IDORScanner{
		sessions: sessions,
		output:   output,
		logger:   logger,
	}
}

// ScanEndpoint tests an endpoint for IDOR by swapping auth contexts
func (i *IDORScanner) ScanEndpoint(endpoint string, method string) []core.Result {
	var results []core.Result

	// 1. Send as high-priv user
	highResp, err := i.sessions.SendRequest(method, endpoint, "high", nil)
	if err != nil {
		return results
	}
	highBody := readBody(highResp)
	highStatus := highResp.StatusCode

	// 2. Send as low-priv user
	lowResp, err := i.sessions.SendRequest(method, endpoint, "low", nil)
	if err != nil {
		return results
	}
	lowBody := readBody(lowResp)
	lowStatus := lowResp.StatusCode

	// 3. Send with no auth
	noAuthResp, err := i.sessions.SendUnauthenticated(method, endpoint)
	if err != nil {
		return results
	}
	noAuthBody := readBody(noAuthResp)
	noAuthStatus := noAuthResp.StatusCode

	// Check for IDOR: low-priv gets same data as high-priv
	if highStatus == 200 && lowStatus == 200 {
		similarity := calculateSimilarity(highBody, lowBody)
		if similarity > 0.8 {
			results = append(results, core.Result{
				Type:     "idor",
				URL:      endpoint,
				Source:   "idor-scanner",
				Tool:     "idor-scanner",
				Severity: "HIGH",
				Evidence: fmt.Sprintf("Low-priv user got %.0f%% similar response to high-priv (status %d)",
					similarity*100, lowStatus),
			})
		}
	}

	// Check for missing auth: no-auth gets data
	if highStatus == 200 && noAuthStatus == 200 {
		similarity := calculateSimilarity(highBody, noAuthBody)
		if similarity > 0.5 {
			results = append(results, core.Result{
				Type:     "auth-bypass",
				URL:      endpoint,
				Source:   "idor-scanner",
				Tool:     "idor-scanner",
				Severity: "CRITICAL",
				Evidence: fmt.Sprintf("Unauthenticated access returns %.0f%% similar response (status %d)",
					similarity*100, noAuthStatus),
			})
		}
	}

	return results
}

// DetectIDPatterns finds URL patterns with incrementable IDs
func (i *IDORScanner) DetectIDPatterns(urls []string) []IDPattern {
	var patterns []IDPattern

	// Pattern: /api/users/123
	pathIDRegex := regexp.MustCompile(`/(\d{1,10})(?:/|$)`)
	// Pattern: ?id=456
	queryIDRegex := regexp.MustCompile(`[?&](id|user_id|uid|account|order|doc|file|report|ticket)=(\d+)`)

	seen := core.NewStringSet()

	for _, u := range urls {
		// Check path-based IDs
		if matches := pathIDRegex.FindStringSubmatch(u); len(matches) > 1 {
			key := pathIDRegex.ReplaceAllString(u, "/{ID}")
			if seen.Add(key) {
				patterns = append(patterns, IDPattern{
					URL:        u,
					ParamValue: matches[1],
					IsPath:     true,
				})
			}
		}

		// Check query-based IDs
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		for param, values := range parsed.Query() {
			if queryIDRegex.MatchString(param + "=" + values[0]) {
				key := parsed.Path + "?" + param
				if seen.Add(key) {
					patterns = append(patterns, IDPattern{
						URL:        u,
						ParamName:  param,
						ParamValue: values[0],
						IsPath:     false,
					})
				}
			}
		}
	}

	return patterns
}

// TestIDSwap tests an ID pattern by incrementing/decrementing the ID
func (i *IDORScanner) TestIDSwap(pattern IDPattern, sessionName string) []core.Result {
	var results []core.Result

	id, err := strconv.Atoi(pattern.ParamValue)
	if err != nil {
		return results
	}

	// Try ID+1 and ID-1
	for _, newID := range []int{id + 1, id - 1, id + 100} {
		var testURL string
		if pattern.IsPath {
			testURL = strings.Replace(pattern.URL, "/"+pattern.ParamValue, "/"+strconv.Itoa(newID), 1)
		} else {
			parsed, _ := url.Parse(pattern.URL)
			q := parsed.Query()
			q.Set(pattern.ParamName, strconv.Itoa(newID))
			parsed.RawQuery = q.Encode()
			testURL = parsed.String()
		}

		resp, err := i.sessions.SendRequest("GET", testURL, sessionName, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == 200 {
			results = append(results, core.Result{
				Type:      "idor",
				URL:       testURL,
				Source:    "idor-scanner",
				Tool:      "idor-scanner",
				Parameter: pattern.ParamName,
				Value:     strconv.Itoa(newID),
				Severity:  "HIGH",
				Evidence:  fmt.Sprintf("ID swap %s→%d returned 200", pattern.ParamValue, newID),
			})
		}
	}

	return results
}

// readBody reads and returns response body as string
func readBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

// calculateSimilarity returns a 0.0-1.0 similarity score between two strings
func calculateSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	// Simple length-based + content overlap heuristic
	shorter, longer := a, b
	if len(a) > len(b) {
		shorter, longer = b, a
	}

	lengthRatio := float64(len(shorter)) / float64(len(longer))

	// Count matching lines
	aLines := strings.Split(a, "\n")
	bLines := strings.Split(b, "\n")
	bLineSet := make(map[string]bool)
	for _, line := range bLines {
		bLineSet[strings.TrimSpace(line)] = true
	}

	matching := 0
	for _, line := range aLines {
		if bLineSet[strings.TrimSpace(line)] {
			matching++
		}
	}

	lineRatio := 0.0
	if len(aLines) > 0 {
		lineRatio = float64(matching) / float64(len(aLines))
	}

	return (lengthRatio + lineRatio) / 2.0
}
