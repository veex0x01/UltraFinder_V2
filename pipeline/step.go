package pipeline

import (
	"time"

	"github.com/veex0x01/ultrafinder/core"
)

// StepResult holds output from a pipeline step
type StepResult struct {
	Name      string                 // Step name
	Results   []core.Result          // Findings
	URLs      []string               // Discovered URLs (passed to next step)
	Hosts     []string               // Discovered hosts
	RawOutput []byte                 // Raw stdout from external tools
	Error     error
	Duration  time.Duration
	Status    string                 // "success", "failed", "skipped"
	Metadata  map[string]interface{}
}

// Step is the interface every pipeline step must implement
type Step interface {
	Name() string                                                                    // Unique step identifier
	Description() string                                                             // Human-readable description
	Category() string                                                                // "recon", "crawl", "vuln", "output", "filter", "transform"
	RequiredTools() []string                                                         // External binaries needed
	Validate(config map[string]interface{}) error                                    // Validate step config before run
	Run(ctx *PipelineContext, config map[string]interface{}) (*StepResult, error)
}

// StepDefinition represents a step as parsed from YAML
type StepDefinition struct {
	Name      string                 `yaml:"name"`
	Type      string                 `yaml:"type"`
	DependsOn interface{}            `yaml:"depends_on,omitempty"` // string or []string
	Config    map[string]interface{} `yaml:"config,omitempty"`
	OutputAs  string                 `yaml:"output_as,omitempty"`
	Condition string                 `yaml:"condition,omitempty"`
}

// GetDependencies returns the depends_on as a string slice
func (sd *StepDefinition) GetDependencies() []string {
	if sd.DependsOn == nil {
		return nil
	}

	switch v := sd.DependsOn.(type) {
	case string:
		return []string{v}
	case []interface{}:
		deps := make([]string, 0, len(v))
		for _, d := range v {
			if s, ok := d.(string); ok {
				deps = append(deps, s)
			}
		}
		return deps
	}
	return nil
}
