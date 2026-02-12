package vulnscan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/veex0x01/ultrafinder/core"
)

// CVE represents a known vulnerability
type CVE struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	CVSS        float64  `json:"cvss"`
	Published   string   `json:"published"`
	References  []string `json:"references"`
	AffectedCPE string   `json:"affected_cpe"`
}

// CVEMapper maps detected technologies to known CVEs
type CVEMapper struct {
	client    *http.Client
	cache     map[string][]CVE
	cacheFile string
	mu        sync.Mutex
}

// NewCVEMapper creates a new CVE mapper
func NewCVEMapper(cacheDir string) *CVEMapper {
	cacheFile := ""
	if cacheDir != "" {
		cacheFile = filepath.Join(cacheDir, "cve_cache.json")
	}

	cm := &CVEMapper{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache:     make(map[string][]CVE),
		cacheFile: cacheFile,
	}

	// Load cache from disk if available
	cm.loadCache()

	return cm
}

// LookupByTech queries NVD API for CVEs matching a technology
func (cm *CVEMapper) LookupByTech(tech Technology) ([]CVE, error) {
	if tech.CPE == "" {
		return nil, nil
	}

	cpe := tech.CPE
	if tech.Version != "" {
		cpe += ":" + tech.Version
	}

	return cm.LookupByCPE(cpe)
}

// LookupByCPE queries NVD API directly with a CPE string
func (cm *CVEMapper) LookupByCPE(cpe string) ([]CVE, error) {
	cm.mu.Lock()
	if cached, ok := cm.cache[cpe]; ok {
		cm.mu.Unlock()
		return cached, nil
	}
	cm.mu.Unlock()

	// Query NVD API v2.0
	apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s&resultsPerPage=20", cpe)

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "UltraFinder/2.0")

	resp, err := cm.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("NVD API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	cves := cm.parseNVDResponse(body, cpe)

	// Cache results
	cm.mu.Lock()
	cm.cache[cpe] = cves
	cm.mu.Unlock()
	cm.saveCache()

	return cves, nil
}

// parseNVDResponse parses NVD API v2.0 JSON response
func (cm *CVEMapper) parseNVDResponse(data []byte, cpe string) []CVE {
	var response struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Description struct {
					Descriptions []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"descriptions"`
				} `json:"descriptions"`
				Metrics struct {
					CvssMetricV31 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
				Published  string `json:"published"`
				References []struct {
					URL string `json:"url"`
				} `json:"references"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(data, &response); err != nil {
		return nil
	}

	var cves []CVE
	for _, vuln := range response.Vulnerabilities {
		cve := CVE{
			ID:          vuln.CVE.ID,
			Published:   vuln.CVE.Published,
			AffectedCPE: cpe,
		}

		// Description
		for _, desc := range vuln.CVE.Description.Descriptions {
			if desc.Lang == "en" {
				cve.Description = desc.Value
				break
			}
		}

		// CVSS Score & Severity
		if len(vuln.CVE.Metrics.CvssMetricV31) > 0 {
			cve.CVSS = vuln.CVE.Metrics.CvssMetricV31[0].CvssData.BaseScore
			cve.Severity = vuln.CVE.Metrics.CvssMetricV31[0].CvssData.BaseSeverity
		}

		// References
		for _, ref := range vuln.CVE.References {
			cve.References = append(cve.References, ref.URL)
		}

		cves = append(cves, cve)
	}

	return cves
}

// MapAll takes all detected technologies and returns all matching CVEs
func (cm *CVEMapper) MapAll(techs []Technology) []CVE {
	var allCVEs []CVE
	for _, tech := range techs {
		cves, err := cm.LookupByTech(tech)
		if err != nil {
			continue
		}
		allCVEs = append(allCVEs, cves...)
	}
	return allCVEs
}

// ToResults converts CVEs to core.Result
func (cm *CVEMapper) ToResults(urlStr string, cves []CVE) []core.Result {
	results := make([]core.Result, 0, len(cves))
	for _, cve := range cves {
		r := core.Result{
			Type:     "cve",
			URL:      urlStr,
			Source:   "cve-mapper",
			CVEID:    cve.ID,
			Severity: cve.Severity,
			Tool:     "cve-mapper",
			Evidence: cve.Description,
		}
		if len(cve.Description) > 200 {
			r.Evidence = cve.Description[:200] + "..."
		}
		results = append(results, r)
	}
	return results
}

func (cm *CVEMapper) loadCache() {
	if cm.cacheFile == "" {
		return
	}
	data, err := os.ReadFile(cm.cacheFile)
	if err != nil {
		return
	}
	json.Unmarshal(data, &cm.cache)
}

func (cm *CVEMapper) saveCache() {
	if cm.cacheFile == "" {
		return
	}
	data, _ := json.MarshalIndent(cm.cache, "", "  ")
	os.MkdirAll(filepath.Dir(cm.cacheFile), 0755)
	os.WriteFile(cm.cacheFile, data, 0644)
}
