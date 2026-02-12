package integrations

import (
	"os"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// SQLMapStep wraps SQLMap for SQL injection testing
type SQLMapStep struct {
	Runner *ToolRunner
}

func (s *SQLMapStep) Name() string           { return "sqlmap" }
func (s *SQLMapStep) Description() string     { return "SQL injection detection via SQLMap" }
func (s *SQLMapStep) Category() string        { return "vuln" }
func (s *SQLMapStep) RequiredTools() []string { return []string{"sqlmap"} }

func (s *SQLMapStep) Validate(config map[string]interface{}) error {
	return nil
}

func (s *SQLMapStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Filter: only URLs with SQLi-prone parameters
	sqliParams := []string{"id", "user", "uid", "name", "query", "search", "page",
		"order", "sort", "category", "item", "product", "num", "count"}

	var targetURLs []string
	allURLs := ctx.GetAllURLs()
	for _, u := range allURLs {
		if hasMatchingParam(u, sqliParams) {
			targetURLs = append(targetURLs, u)
		}
	}

	if len(targetURLs) == 0 {
		return &pipeline.StepResult{Name: "sqlmap"}, nil
	}

	urlFile, err := WriteURLListToTempFile(targetURLs)
	if err != nil {
		return nil, err
	}
	defer os.Remove(urlFile)

	args := []string{
		"-m", urlFile,
		"--batch",
		"--random-agent",
		"--level", getStringConfig(config, "level", "1"),
		"--risk", getStringConfig(config, "risk", "1"),
	}

	if ctx.WorkDir != "" {
		args = append(args, "--output-dir", ctx.WorkDir+"/sqlmap-output")
	}

	result, err := s.Runner.Run(ctx.Context, RunConfig{
		Name:    "sqlmap",
		Binary:  "sqlmap",
		Args:    args,
		Timeout: 30 * time.Minute,
	})
	if err != nil {
		return nil, err
	}

	return s.parseSQLMapOutput(result, targetURLs)
}

func (s *SQLMapStep) parseSQLMapOutput(result *RunResult, targetURLs []string) (*pipeline.StepResult, error) {
	stepResult := &pipeline.StepResult{
		Name:      "sqlmap",
		RawOutput: result.Stdout,
	}

	// Parse stdout for injection findings
	lines := parseLines(result.Stdout)
	for _, line := range lines {
		if len(line) > 20 {
			// SQLMap outputs lines like: "Parameter: id (GET)" and "Type: boolean-based blind"
			if containsAny(line, []string{"is vulnerable", "injection", "sqlmap identified"}) {
				stepResult.Results = append(stepResult.Results, core.Result{
					Type:     "sqli",
					URL:      targetURLs[0], // Simplified — real parsing would correlate
					Source:   "sqlmap",
					Tool:     "sqlmap",
					Severity: "CRITICAL",
					Evidence: line,
				})
			}
		}
	}

	return stepResult, nil
}

func containsAny(s string, substrs []string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
