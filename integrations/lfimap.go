package integrations

import (
	"strings"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// LFIMapStep wraps LFIMap for Local File Inclusion testing
type LFIMapStep struct {
	Runner *ToolRunner
}

func (l *LFIMapStep) Name() string           { return "lfimap" }
func (l *LFIMapStep) Description() string     { return "Local File Inclusion detection via LFIMap" }
func (l *LFIMapStep) Category() string        { return "vuln" }
func (l *LFIMapStep) RequiredTools() []string { return []string{"lfimap"} }

func (l *LFIMapStep) Validate(config map[string]interface{}) error {
	return nil
}

func (l *LFIMapStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Filter: URLs with file/path/include parameters
	lfiParams := []string{"file", "path", "page", "include", "inc", "template",
		"load", "read", "doc", "document", "folder", "root", "pg", "style",
		"content", "dir", "site", "type", "view", "layout"}

	var targetURLs []string
	for _, u := range ctx.GetAllURLs() {
		if hasMatchingParam(u, lfiParams) {
			targetURLs = append(targetURLs, u)
		}
	}

	if len(targetURLs) == 0 {
		return &pipeline.StepResult{Name: "lfimap"}, nil
	}

	// LFIMap processes one URL at a time
	var allResults []core.Result
	for _, targetURL := range targetURLs {
		args := []string{"-U", targetURL}
		result, err := l.Runner.Run(ctx.Context, RunConfig{
			Name:    "lfimap",
			Binary:  "lfimap",
			Args:    args,
			Timeout: 5 * time.Minute,
		})
		if err != nil {
			continue
		}
		allResults = append(allResults, l.parseLFIMapOutput(result, targetURL)...)
	}

	return &pipeline.StepResult{
		Name:    "lfimap",
		Results: allResults,
	}, nil
}

func (l *LFIMapStep) parseLFIMapOutput(result *RunResult, targetURL string) []core.Result {
	var results []core.Result

	lines := parseLines(result.Stdout)
	for _, line := range lines {
		lowerLine := strings.ToLower(line)
		if strings.Contains(lowerLine, "vulnerable") || strings.Contains(lowerLine, "lfi") {
			results = append(results, core.Result{
				Type:     "lfi",
				URL:      targetURL,
				Source:   "lfimap",
				Tool:     "lfimap",
				Severity: "HIGH",
				Evidence: line,
			})
		}
	}

	return results
}
