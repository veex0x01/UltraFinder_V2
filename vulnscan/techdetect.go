package vulnscan

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/veex0x01/ultrafinder/core"
)

//go:embed signatures/technologies.json
var signaturesJSON []byte

// Technology represents a detected technology
type Technology struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Categories []string `json:"categories"`
	CPE        string   `json:"cpe,omitempty"`
	Confidence int      `json:"confidence"` // 0-100
}

// TechSignature is a single technology fingerprint from the database
type TechSignature struct {
	Name       string            `json:"name"`
	Categories []string          `json:"categories"`
	Headers    map[string]string `json:"headers,omitempty"`
	HTML       []string          `json:"html,omitempty"`
	Scripts    []string          `json:"scripts,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`
	Cookies    map[string]string `json:"cookies,omitempty"`
	Implies    []string          `json:"implies,omitempty"`
	CPE        string            `json:"cpe,omitempty"`
}

type sigDB struct {
	Technologies []TechSignature `json:"technologies"`
}

// TechDetector detects technologies from HTTP responses
type TechDetector struct {
	signatures []TechSignature
	detected   map[string]*Technology
	mu         sync.Mutex
}

// NewTechDetector creates a new TechDetector loading the embedded signature DB
func NewTechDetector() (*TechDetector, error) {
	var db sigDB
	if err := json.Unmarshal(signaturesJSON, &db); err != nil {
		return nil, err
	}
	return &TechDetector{
		signatures: db.Technologies,
		detected:   make(map[string]*Technology),
	}, nil
}

// DetectFromResponse analyzes a single HTTP response for technologies
func (td *TechDetector) DetectFromResponse(urlStr string, statusCode int,
	headers http.Header, body []byte) []Technology {

	var found []Technology
	bodyStr := string(body)

	found = append(found, td.DetectFromHeaders(headers)...)
	found = append(found, td.DetectFromHTML(bodyStr)...)
	found = append(found, td.DetectFromScripts(bodyStr)...)
	found = append(found, td.DetectFromCookies(headers)...)

	// Deduplicate and store
	for i := range found {
		td.mu.Lock()
		if existing, ok := td.detected[found[i].Name]; ok {
			if found[i].Confidence > existing.Confidence {
				td.detected[found[i].Name] = &found[i]
			}
			if found[i].Version != "" && existing.Version == "" {
				existing.Version = found[i].Version
			}
		} else {
			td.detected[found[i].Name] = &found[i]
		}
		td.mu.Unlock()
	}

	return found
}

// DetectFromHeaders checks response headers against signature DB
func (td *TechDetector) DetectFromHeaders(headers http.Header) []Technology {
	var found []Technology

	for _, sig := range td.signatures {
		if sig.Headers == nil {
			continue
		}
		for headerName, pattern := range sig.Headers {
			values := headers.Values(headerName)
			for _, value := range values {
				if pattern == "" {
					// Header existence is enough
					found = append(found, Technology{
						Name:       sig.Name,
						Categories: sig.Categories,
						CPE:        sig.CPE,
						Confidence: 80,
					})
				} else {
					re, err := regexp.Compile("(?i)" + pattern)
					if err != nil {
						continue
					}
					if matches := re.FindStringSubmatch(value); matches != nil {
						tech := Technology{
							Name:       sig.Name,
							Categories: sig.Categories,
							CPE:        sig.CPE,
							Confidence: 90,
						}
						if len(matches) > 1 && matches[1] != "" {
							tech.Version = matches[1]
						}
						found = append(found, tech)
					}
				}
			}
		}
	}

	return found
}

// DetectFromHTML checks HTML body for technology patterns
func (td *TechDetector) DetectFromHTML(body string) []Technology {
	var found []Technology
	lowerBody := strings.ToLower(body)

	for _, sig := range td.signatures {
		for _, pattern := range sig.HTML {
			if strings.Contains(lowerBody, strings.ToLower(pattern)) {
				found = append(found, Technology{
					Name:       sig.Name,
					Categories: sig.Categories,
					CPE:        sig.CPE,
					Confidence: 70,
				})
				break // One match per sig is enough
			}
		}
	}

	return found
}

// DetectFromScripts checks script src attributes against signature DB
func (td *TechDetector) DetectFromScripts(body string) []Technology {
	var found []Technology

	// Extract script src values
	scriptRe := regexp.MustCompile(`(?i)<script[^>]*src=["']([^"']+)["']`)
	matches := scriptRe.FindAllStringSubmatch(body, -1)

	var scriptSrcs []string
	for _, m := range matches {
		if len(m) > 1 {
			scriptSrcs = append(scriptSrcs, m[1])
		}
	}

	for _, sig := range td.signatures {
		for _, pattern := range sig.Scripts {
			re, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				continue
			}
			for _, src := range scriptSrcs {
				if matches := re.FindStringSubmatch(src); matches != nil {
					tech := Technology{
						Name:       sig.Name,
						Categories: sig.Categories,
						CPE:        sig.CPE,
						Confidence: 85,
					}
					if len(matches) > 1 && matches[1] != "" {
						tech.Version = matches[1]
					}
					found = append(found, tech)
					break
				}
			}
		}
	}

	return found
}

// DetectFromCookies checks Set-Cookie headers against signature DB
func (td *TechDetector) DetectFromCookies(headers http.Header) []Technology {
	var found []Technology

	cookies := headers.Values("Set-Cookie")
	allCookies := strings.Join(cookies, "; ")

	for _, sig := range td.signatures {
		if sig.Cookies == nil {
			continue
		}
		for cookieName := range sig.Cookies {
			if strings.Contains(allCookies, cookieName) {
				found = append(found, Technology{
					Name:       sig.Name,
					Categories: sig.Categories,
					CPE:        sig.CPE,
					Confidence: 95,
				})
				break
			}
		}
	}

	return found
}

// GetAll returns all detected technologies
func (td *TechDetector) GetAll() []Technology {
	td.mu.Lock()
	defer td.mu.Unlock()

	techs := make([]Technology, 0, len(td.detected))
	for _, t := range td.detected {
		techs = append(techs, *t)
	}
	return techs
}

// ToResults converts detected technologies to core.Result
func (td *TechDetector) ToResults(urlStr string) []core.Result {
	techs := td.GetAll()
	results := make([]core.Result, 0, len(techs))

	for _, tech := range techs {
		r := core.Result{
			Type:       "technology",
			URL:        urlStr,
			Source:     "tech-detect",
			Parameter:  tech.Name,
			Value:      tech.Version,
			Confidence: confidenceStr(tech.Confidence),
			Severity:   "INFO",
			Tool:       "tech-detect",
		}
		if tech.CPE != "" {
			r.Evidence = tech.CPE
		}
		results = append(results, r)
	}

	return results
}

func confidenceStr(c int) string {
	if c >= 90 {
		return "High"
	} else if c >= 70 {
		return "Medium"
	}
	return "Low"
}
