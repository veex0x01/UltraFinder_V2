package integrations

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// NucleiStep wraps Nuclei for template-based vulnerability scanning
type NucleiStep struct {
	Runner *ToolRunner
}

func (n *NucleiStep) Name() string           { return "nuclei" }
func (n *NucleiStep) Description() string     { return "Template-based vulnerability scanning via Nuclei" }
func (n *NucleiStep) Category() string        { return "vuln" }
func (n *NucleiStep) RequiredTools() []string { return []string{"nuclei"} }

func (n *NucleiStep) Validate(config map[string]interface{}) error {
	return nil
}

func (n *NucleiStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Collect target URLs
	var urls []string
	if targetsFrom, ok := config["targets_from"].(string); ok {
		urls = ctx.GetURLsFromStep(targetsFrom)
	}
	if len(urls) == 0 {
		urls = []string{ctx.TargetURL}
	}

	// Smart Scan: Check for technologies from previous step
	var techTags []string
	if techFrom, ok := config["technologies_from"].(string); ok {
		results := ctx.GetResultsFromStep(techFrom)
		seen := make(map[string]bool)
		for _, r := range results {
			if r.Type == "technology" {
				// Normalize tech names (e.g., WordPress -> wordpress)
				tech := strings.ToLower(r.Value)
				// Map common tech to nuclei tags if needed, but usually they match
				// e.g. apache, nginx, php, wordpress, drupal
				if !seen[tech] {
					techTags = append(techTags, tech)
					seen[tech] = true
				}
			}
		}
		if len(techTags) > 0 {
			ctx.Logger.Success("Smart Scan: Detected technologies: %v", techTags)
		}
	}

	urlFile, err := WriteURLListToTempFile(urls)
	if err != nil {
		return nil, err
	}
	defer os.Remove(urlFile)

	// Determine arguments based on Smart Scan vs Default
	args := []string{
		"-l", urlFile,
		"-jsonl",
		"-stats",   // Show progress stats
		"-v",       // Verbose mode for visibility
		"-nc",      // No color
	}

	// If tech detected, prioritize tags
	if len(techTags) > 0 {
		// Use tags for detected tech
		tags := strings.Join(techTags, ",")
		args = append(args, "-tags", tags)
	} else {
		// Fallback to configured templates or default
		if templates, ok := config["templates"].([]interface{}); ok {
			for _, t := range templates {
				args = append(args, "-t", fmt.Sprint(t))
			}
		}
		// If no templates specified, Nuclei runs default scan. 
		// User config usually specifies severity, so we add it here if NOT smart scanning?
		// Or assume severity applies to tagged scan too? Yes.
	}

	// Severity (always apply)
	severity := getStringConfig(config, "severity", "critical,high")
	args = append(args, "-severity", severity)

	if threads, ok := config["threads"]; ok {
		args = append(args, "-c", fmt.Sprint(threads))
	}

	if rateLimit, ok := config["rate_limit"]; ok {
		args = append(args, "-rl", fmt.Sprint(rateLimit))
	}

	// Add exclude tags if configured
	if excludeTags, ok := config["exclude_tags"].(string); ok {
		args = append(args, "-etags", excludeTags)
	}

	// Add explicit include tags (on top of smart tags)
	if includeTags, ok := config["tags"].(string); ok {
		args = append(args, "-tags", includeTags)
	}

	result, err := n.Runner.Run(ctx.Context, RunConfig{
		Name:         "nuclei",
		Binary:       "nuclei",
		Args:         args,
		Timeout:      30 * time.Minute,
		StreamOutput: true, // Stream output to console
	})
	if err != nil {
		return nil, err
	}

	return n.parseNucleiOutput(result.Stdout)
}

// nucleiResult represents a single Nuclei JSONL output line
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Type       string `json:"type"`
	Severity   string `json:"info.severity"`
	Name       string `json:"info.name"`
	Info       struct {
		Name        string `json:"name"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
	} `json:"info"`
	MatcherName string `json:"matcher-name"`
	ExtractedResults []string `json:"extracted-results"`
}

func (n *NucleiStep) parseNucleiOutput(data []byte) (*pipeline.StepResult, error) {
	stepResult := &pipeline.StepResult{
		Name: "nuclei",
	}

	lines := parseLines(data)
	for _, line := range lines {
		var nr nucleiResult
		if err := json.Unmarshal([]byte(line), &nr); err != nil {
			continue
		}

		severity := nr.Info.Severity
		if severity == "" {
			severity = "INFO"
		}

		result := core.Result{
			Type:     "vulnerability",
			URL:      nr.MatchedAt,
			Source:   "nuclei",
			Tool:     "nuclei",
			Severity: mapNucleiSeverity(severity),
			Evidence: nr.Info.Description,
			Value:    nr.Info.Name,
		}

		if nr.TemplateID != "" {
			result.Parameter = nr.TemplateID
		}

		stepResult.Results = append(stepResult.Results, result)
		if nr.MatchedAt != "" {
			stepResult.URLs = append(stepResult.URLs, nr.MatchedAt)
		}
	}

	return stepResult, nil
}

func mapNucleiSeverity(s string) string {
	switch s {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	default:
		return "INFO"
	}
}
