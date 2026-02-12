package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// TechFinderStep runs the external techfinder binary for accurate tech detection
type TechFinderStep struct {
	Runner *ToolRunner
}

func (tf *TechFinderStep) Name() string           { return "techfinder" }
func (tf *TechFinderStep) Description() string    { return "Advanced technology detection with CPE" }
func (tf *TechFinderStep) Category() string       { return "recon" }
func (tf *TechFinderStep) RequiredTools() []string { return []string{} }

func (tf *TechFinderStep) Validate(config map[string]interface{}) error {
	return nil
}

func (tf *TechFinderStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Collect URLs
	var urls []string
	if targetsFrom, ok := config["targets_from"].(string); ok {
		urls = ctx.GetURLsFromStep(targetsFrom)
	}
	if len(urls) == 0 {
		urls = []string{ctx.TargetURL}
	}

	stepResult := &pipeline.StepResult{
		Name: "techfinder",
	}

	// Run techfinder for each URL
	for _, targetURL := range urls {
		ctx.Logger.Info("Analyzing %s with TechFinder...", targetURL)

		var stdout, stderr bytes.Buffer
		var err error
		
		// Retry up to 2 times (TechFinder can be flaky due to browser timeouts)
		maxRetries := 2
		for attempt := 0; attempt < maxRetries; attempt++ {
			if attempt > 0 {
				ctx.Logger.Info("Retrying TechFinder (attempt %d/%d)...", attempt+1, maxRetries)
				time.Sleep(5 * time.Second) // Wait before retry
			}
			
			// Run techfinder binary (use absolute path or check if in PATH)
			cmdCtx, cancel := context.WithTimeout(ctx.Context, 90*time.Second)
			
			// Try techfinder in same directory first, then PATH
			// Use -w 90000 to increase internal timeout to 90s (default is 30s)
			cmd := exec.CommandContext(cmdCtx, "./techFinder/techfinder", targetURL, "-p", "-w", "90000")
			stdout.Reset()
			stderr.Reset()
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err = cmd.Run()
			cancel()
			
			if err == nil {
				break // Success!
			}
		}
		
		if err != nil {
			if stderr.Len() > 0 {
				ctx.Logger.Warn("TechFinder stderr: %s", stderr.String())
			}
			ctx.Logger.Warn("TechFinder failed for %s after %d attempts: %v", targetURL, maxRetries, err)
			continue
		}

		// Parse JSON output
		var result TechFinderOutput
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			ctx.Logger.Warn("Failed to parse TechFinder output: %v", err)
			continue
		}

		ctx.Logger.Success("Found %d technologies for %s", len(result.Technologies), targetURL)

		// Convert to Results
		for _, tech := range result.Technologies {
			techResult := core.Result{
				Type:   "technology",
				URL:    targetURL,
				Value:  tech.Name,
				Source: "techfinder",
			}

			// Add version if detected
			if tech.Version != nil && *tech.Version != "" {
				techResult.Evidence = *tech.Version
				techResult.Parameter = fmt.Sprintf("%s/%s", tech.Name, *tech.Version)
				ctx.Logger.Success("  [%s] %s/%s (confidence: %d%%)", 
					strings.Join(tech.Categories, ", "), tech.Name, *tech.Version, tech.Confidence)
			} else {
				techResult.Parameter = tech.Name
				ctx.Logger.Success("  [%s] %s (confidence: %d%%)", 
					strings.Join(tech.Categories, ", "), tech.Name, tech.Confidence)
			}

			// Store CPE if available
			if tech.CPE != nil {
				techResult.Evidence = *tech.CPE
			}

			stepResult.Results = append(stepResult.Results, techResult)
		}
	}

	return stepResult, nil
}

// TechFinderOutput represents the JSON output from techfinder
type TechFinderOutput struct {
	Target       string       `json:"target"`
	Technologies []Technology `json:"technologies"`
}

// Technology represents a detected technology
type Technology struct {
	Name       string    `json:"name"`
	Version    *string   `json:"version"`
	Confidence int       `json:"confidence"`
	CPE        *string   `json:"cpe"`
	Categories []string  `json:"categories"`
}
