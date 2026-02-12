package monitor

import (
	"crypto/md5"
	"encoding/hex"
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

// DiffMonitor monitors web pages for content changes
type DiffMonitor struct {
	StorageDir string
	Client     *http.Client
	Logger     *reporting.Logger
}

// DiffResult holds change detection output
type DiffResult struct {
	URL       string
	Changed   bool
	OldHash   string
	NewHash   string
	OldSize   int
	NewSize   int
	Additions []string
	Removals  []string
}

// NewDiffMonitor creates a new diff monitor
func NewDiffMonitor(storageDir string, logger *reporting.Logger) *DiffMonitor {
	os.MkdirAll(storageDir, 0755)
	return &DiffMonitor{
		StorageDir: storageDir,
		Client:     &http.Client{Timeout: 15 * time.Second},
		Logger:     logger,
	}
}

// CheckForChanges fetches a URL and compares with the stored version
func (d *DiffMonitor) CheckForChanges(urlStr string) (*DiffResult, error) {
	// Fetch current version
	resp, err := d.Client.Get(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", urlStr, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	currentContent := string(body)
	currentHash := hashContent(currentContent)

	// Load stored version
	storedPath := d.getStoragePath(urlStr)
	storedContent, storedHash, err := d.loadStored(storedPath)

	result := &DiffResult{
		URL:     urlStr,
		NewHash: currentHash,
		NewSize: len(currentContent),
	}

	if err == nil && storedHash != "" {
		result.OldHash = storedHash
		result.OldSize = len(storedContent)

		if currentHash != storedHash {
			result.Changed = true
			result.Additions, result.Removals = computeDiff(storedContent, currentContent)
			d.Logger.Warn("Content change detected: %s", urlStr)
		}
	}

	// Store current version
	d.store(storedPath, currentContent, currentHash)

	return result, nil
}

// ToResult converts a DiffResult to core.Result
func (d *DiffMonitor) ToResult(dr *DiffResult) *core.Result {
	if !dr.Changed {
		return nil
	}

	return &core.Result{
		Type:     "content-diff",
		URL:      dr.URL,
		Source:   "diff-monitor",
		Tool:     "diff-monitor",
		Severity: "MEDIUM",
		Evidence: fmt.Sprintf("Content changed: %d additions, %d removals, old hash: %s, new hash: %s",
			len(dr.Additions), len(dr.Removals), dr.OldHash[:8], dr.NewHash[:8]),
	}
}

func (d *DiffMonitor) getStoragePath(urlStr string) string {
	hash := hashContent(urlStr)
	return filepath.Join(d.StorageDir, hash+".dat")
}

func (d *DiffMonitor) loadStored(path string) (string, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}

	content := string(data)
	hash := hashContent(content)
	return content, hash, nil
}

func (d *DiffMonitor) store(path, content, hash string) {
	os.WriteFile(path, []byte(content), 0644)
}

func hashContent(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// computeDiff performs a simple line-based diff
func computeDiff(old, new string) (additions, removals []string) {
	oldLines := strings.Split(old, "\n")
	newLines := strings.Split(new, "\n")

	oldSet := make(map[string]bool)
	for _, line := range oldLines {
		oldSet[strings.TrimSpace(line)] = true
	}

	newSet := make(map[string]bool)
	for _, line := range newLines {
		newSet[strings.TrimSpace(line)] = true
	}

	for _, line := range newLines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !oldSet[trimmed] {
			additions = append(additions, trimmed)
		}
	}

	for _, line := range oldLines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !newSet[trimmed] {
			removals = append(removals, trimmed)
		}
	}

	return
}
