package reporting

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/veex0x01/ultrafinder/core"
)

// ExportCSV writes results to a CSV file
func ExportCSV(outputPath string, results []core.Result) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// Header
	header := []string{
		"Type", "URL", "Source", "Parameter", "Value",
		"Confidence", "StatusCode", "Severity", "CVEID",
		"Tool", "Evidence", "Timestamp",
	}
	if err := w.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Rows
	for _, r := range results {
		row := []string{
			r.Type, r.URL, r.Source, r.Parameter, r.Value,
			r.Confidence, fmt.Sprint(r.StatusCode), r.Severity, r.CVEID,
			r.Tool, r.Evidence, r.Timestamp,
		}
		if err := w.Write(row); err != nil {
			return fmt.Errorf("failed to write CSV row: %w", err)
		}
	}

	return nil
}
