package reporting

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/veex0x01/ultrafinder/core"
)

// JSONExport represents a structured JSON export
type JSONExport struct {
	Tool      string        `json:"tool"`
	Version   string        `json:"version"`
	Target    string        `json:"target"`
	Timestamp string        `json:"timestamp"`
	Duration  string        `json:"duration"`
	Stats     ScanStats     `json:"stats"`
	Results   []core.Result `json:"results"`
}

// ExportJSON writes results to a structured JSON file
func ExportJSON(outputPath, target string, results []core.Result, stats ScanStats, duration time.Duration) error {
	export := JSONExport{
		Tool:      "UltraFinder",
		Version:   "2.0.0",
		Target:    target,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Duration:  duration.String(),
		Stats:     stats,
		Results:   results,
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	return os.WriteFile(outputPath, data, 0644)
}

// ExportJSONL writes results as JSON Lines (one JSON object per line)
func ExportJSONL(outputPath string, results []core.Result) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create JSONL file: %w", err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	for _, result := range results {
		if err := encoder.Encode(result); err != nil {
			return fmt.Errorf("failed to encode result: %w", err)
		}
	}

	return nil
}
