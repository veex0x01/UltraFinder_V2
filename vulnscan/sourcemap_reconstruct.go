package vulnscan

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/reporting"
)

// SourceMapReconstructor downloads and reconstructs source from .map files
type SourceMapReconstructor struct {
	client    *http.Client
	outputDir string
	logger    *reporting.Logger
}

// ReconstructResult holds the result of a source map reconstruction
type ReconstructResult struct {
	MapURL      string
	SourceFiles []string
	TotalFiles  int
	TotalSize   int64
	Secrets     []core.Result
	Endpoints   []core.Result
}

// sourceMap represents a v3 source map file
type sourceMap struct {
	Version        int      `json:"version"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
	Names          []string `json:"names"`
}

// NewSourceMapReconstructor creates a new reconstructor
func NewSourceMapReconstructor(outputDir string, logger *reporting.Logger) *SourceMapReconstructor {
	return &SourceMapReconstructor{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		outputDir: outputDir,
		logger:    logger,
	}
}

// ReconstructFromURL downloads a .map file and reconstructs original sources
func (s *SourceMapReconstructor) ReconstructFromURL(mapURL string) (*ReconstructResult, error) {
	// Download the .map file
	req, err := http.NewRequest("GET", mapURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download source map: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("source map returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Parse source map
	var sm sourceMap
	if err := json.Unmarshal(body, &sm); err != nil {
		return nil, fmt.Errorf("failed to parse source map: %w", err)
	}

	if sm.Version != 3 {
		return nil, fmt.Errorf("unsupported source map version: %d", sm.Version)
	}

	result := &ReconstructResult{
		MapURL:     mapURL,
		TotalFiles: len(sm.Sources),
	}

	// Reconstruct source files
	for i, sourcePath := range sm.Sources {
		if i >= len(sm.SourcesContent) {
			break
		}

		content := sm.SourcesContent[i]
		if content == "" {
			continue
		}

		// Sanitize path
		cleanPath := sanitizePath(sourcePath)
		if cleanPath == "" {
			continue
		}

		outPath := filepath.Join(s.outputDir, cleanPath)

		// Create directory structure
		if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
			continue
		}

		// Write source file
		if err := os.WriteFile(outPath, []byte(content), 0644); err != nil {
			continue
		}

		result.SourceFiles = append(result.SourceFiles, outPath)
		result.TotalSize += int64(len(content))

		// Scan reconstructed source for secrets and endpoints
		secrets := scanForSecrets(mapURL, content)
		endpoints := scanForEndpoints(mapURL, content)
		result.Secrets = append(result.Secrets, secrets...)
		result.Endpoints = append(result.Endpoints, endpoints...)
	}

	if s.logger != nil {
		s.logger.Success("Reconstructed %d source files (%d bytes) from %s",
			len(result.SourceFiles), result.TotalSize, mapURL)
	}

	return result, nil
}

// sanitizePath cleans a source path for safe filesystem writing
func sanitizePath(p string) string {
	// Remove leading ../ or ./
	for strings.HasPrefix(p, "../") {
		p = p[3:]
	}
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	// Remove webpack:// prefix
	p = strings.TrimPrefix(p, "webpack:///")
	p = strings.TrimPrefix(p, "webpack://")

	// Skip node_modules
	if strings.Contains(p, "node_modules/") {
		return ""
	}

	return p
}

// scanForSecrets scans reconstructed source for API keys and secrets
func scanForSecrets(sourceURL, content string) []core.Result {
	var results []core.Result

	for _, pattern := range core.APIKeyPatterns {
		if matches := pattern.Pattern.FindAllString(content, -1); len(matches) > 0 {
			for _, match := range matches {
				results = append(results, core.Result{
					Type:     "secret",
					URL:      sourceURL,
					Source:   "source-map",
					Value:    match,
					Severity: "HIGH",
					Tool:     "source-map-reconstruct",
					Evidence: fmt.Sprintf("Found %s in reconstructed source", pattern.Name),
				})
			}
		}
	}

	return results
}

// scanForEndpoints scans reconstructed source for API endpoints
func scanForEndpoints(sourceURL, content string) []core.Result {
	var results []core.Result

	for _, pattern := range core.AJAXPatterns {
		if matches := pattern.Pattern.FindAllString(content, -1); len(matches) > 0 {
			for _, match := range matches {
				results = append(results, core.Result{
					Type:   "endpoint",
					URL:    sourceURL,
					Source: "source-map",
					Value:  match,
					Tool:   "source-map-reconstruct",
				})
			}
		}
	}

	return results
}
