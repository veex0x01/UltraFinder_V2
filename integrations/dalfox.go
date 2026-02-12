package integrations

import (
	"encoding/json"
	"os"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// DalfoxStep wraps Dalfox for XSS testing
type DalfoxStep struct {
	Runner *ToolRunner
}

func (d *DalfoxStep) Name() string           { return "dalfox" }
func (d *DalfoxStep) Description() string     { return "XSS vulnerability detection via Dalfox" }
func (d *DalfoxStep) Category() string        { return "vuln" }
func (d *DalfoxStep) RequiredTools() []string { return []string{"dalfox"} }

func (d *DalfoxStep) Validate(config map[string]interface{}) error {
	return nil
}

func (d *DalfoxStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Filter: URLs with query parameters
	var targetURLs []string
	for _, u := range ctx.GetAllURLs() {
		if hasQueryParams(u) {
			targetURLs = append(targetURLs, u)
		}
	}

	if len(targetURLs) == 0 {
		return &pipeline.StepResult{Name: "dalfox"}, nil
	}

	urlFile, err := WriteURLListToTempFile(targetURLs)
	if err != nil {
		return nil, err
	}
	defer os.Remove(urlFile)

	outputFile := ""
	if ctx.WorkDir != "" {
		outputFile = ctx.WorkDir + "/dalfox-output.json"
	}

	args := []string{
		"file", urlFile,
		"--silence",
		"--format", "json",
	}
	if outputFile != "" {
		args = append(args, "--output", outputFile)
	}

	result, err := d.Runner.Run(ctx.Context, RunConfig{
		Name:    "dalfox",
		Binary:  "dalfox",
		Args:    args,
		Timeout: 20 * time.Minute,
	})
	if err != nil {
		return nil, err
	}

	return d.parseDalfoxOutput(result, outputFile)
}

type dalfoxResult struct {
	Type       string `json:"type"`
	InjectType string `json:"inject_type"`
	POC        string `json:"poc"`
	Method     string `json:"method"`
	Data       string `json:"data"`
	Param      string `json:"param"`
	Severity   string `json:"severity"`
}

func (d *DalfoxStep) parseDalfoxOutput(result *RunResult, outputFile string) (*pipeline.StepResult, error) {
	stepResult := &pipeline.StepResult{
		Name: "dalfox",
	}

	// Try to read from output file first
	var data []byte
	if outputFile != "" {
		if fileData, err := os.ReadFile(outputFile); err == nil {
			data = fileData
		}
	}
	if data == nil {
		data = result.Stdout
	}

	lines := parseLines(data)
	for _, line := range lines {
		var dr dalfoxResult
		if err := json.Unmarshal([]byte(line), &dr); err != nil {
			continue
		}

		stepResult.Results = append(stepResult.Results, core.Result{
			Type:      "xss",
			URL:       dr.POC,
			Source:    "dalfox",
			Tool:      "dalfox",
			Parameter: dr.Param,
			Severity:  "HIGH",
			Evidence:  dr.InjectType,
		})
	}

	return stepResult, nil
}
