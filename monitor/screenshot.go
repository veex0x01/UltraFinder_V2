package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/reporting"
)

// ScreenshotEngine takes and compares screenshots
type ScreenshotEngine struct {
	OutputDir string
	Logger    *reporting.Logger
}

// NewScreenshotEngine creates a new screenshot engine
func NewScreenshotEngine(outputDir string, logger *reporting.Logger) *ScreenshotEngine {
	os.MkdirAll(outputDir, 0755)
	return &ScreenshotEngine{
		OutputDir: outputDir,
		Logger:    logger,
	}
}

// TakeScreenshot captures a full-page screenshot using headless Chrome
func (s *ScreenshotEngine) TakeScreenshot(urlStr string) (string, error) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var buf []byte
	err := chromedp.Run(ctx,
		chromedp.Navigate(urlStr),
		chromedp.Sleep(2*time.Second), // Wait for JS rendering
		chromedp.FullScreenshot(&buf, 90),
	)
	if err != nil {
		return "", fmt.Errorf("screenshot failed: %w", err)
	}

	// Save with timestamp-based filename
	fileName := fmt.Sprintf("%s_%s.png",
		sanitizeFilename(urlStr),
		time.Now().Format("20060102_150405"))
	outPath := filepath.Join(s.OutputDir, fileName)

	if err := os.WriteFile(outPath, buf, 0644); err != nil {
		return "", err
	}

	s.Logger.Info("Screenshot saved: %s (%d KB)", outPath, len(buf)/1024)
	return outPath, nil
}

// CompareScreenshots compares two screenshot files and returns similarity 0.0-1.0
func (s *ScreenshotEngine) CompareScreenshots(path1, path2 string) (float64, error) {
	data1, err := os.ReadFile(path1)
	if err != nil {
		return 0, err
	}
	data2, err := os.ReadFile(path2)
	if err != nil {
		return 0, err
	}

	// Size-based quick check
	if len(data1) == 0 || len(data2) == 0 {
		return 0, nil
	}

	// Byte-level comparison (simplified — real impl would use image diff)
	minLen := len(data1)
	if len(data2) < minLen {
		minLen = len(data2)
	}

	matching := 0
	sampleSize := minLen
	if sampleSize > 10000 {
		sampleSize = 10000 // Sample first 10KB for speed
	}

	for i := 0; i < sampleSize; i++ {
		if data1[i] == data2[i] {
			matching++
		}
	}

	return float64(matching) / float64(sampleSize), nil
}

// DetectChanges takes a new screenshot and compares with the latest
func (s *ScreenshotEngine) DetectChanges(urlStr string, threshold float64) (*core.Result, error) {
	// Find latest existing screenshot for this URL
	prefix := sanitizeFilename(urlStr)
	latest := s.findLatestScreenshot(prefix)

	// Take new screenshot
	newPath, err := s.TakeScreenshot(urlStr)
	if err != nil {
		return nil, err
	}

	if latest == "" {
		// First screenshot — no comparison
		return nil, nil
	}

	// Compare
	similarity, err := s.CompareScreenshots(latest, newPath)
	if err != nil {
		return nil, err
	}

	if similarity < threshold {
		s.Logger.Warn("Visual change detected for %s (similarity: %.1f%%)", urlStr, similarity*100)
		return &core.Result{
			Type:     "screenshot-diff",
			URL:      urlStr,
			Source:   "screenshot-monitor",
			Tool:     "screenshot-compare",
			Severity: "MEDIUM",
			Evidence: fmt.Sprintf("Visual change: %.1f%% similarity (threshold: %.1f%%)", similarity*100, threshold*100),
		}, nil
	}

	return nil, nil
}

func (s *ScreenshotEngine) findLatestScreenshot(prefix string) string {
	entries, err := os.ReadDir(s.OutputDir)
	if err != nil {
		return ""
	}

	var latest string
	var latestTime time.Time

	for _, entry := range entries {
		name := entry.Name()
		if len(name) > len(prefix) && name[:len(prefix)] == prefix {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.ModTime().After(latestTime) {
				latestTime = info.ModTime()
				latest = filepath.Join(s.OutputDir, name)
			}
		}
	}

	return latest
}

func sanitizeFilename(urlStr string) string {
	result := make([]byte, 0, len(urlStr))
	for _, c := range urlStr {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'):
			result = append(result, byte(c))
		default:
			result = append(result, '_')
		}
	}
	if len(result) > 100 {
		result = result[:100]
	}
	return string(result)
}
