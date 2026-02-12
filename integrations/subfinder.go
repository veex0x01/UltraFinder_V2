package integrations

import (
	"fmt"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// SubfinderStep wraps Subfinder for passive subdomain enumeration
type SubfinderStep struct {
	Runner *ToolRunner
}

func (s *SubfinderStep) Name() string        { return "subfinder" }
func (s *SubfinderStep) Description() string  { return "Passive subdomain enumeration via Subfinder" }
func (s *SubfinderStep) Category() string     { return "recon" }
func (s *SubfinderStep) RequiredTools() []string { return []string{"subfinder"} }

func (s *SubfinderStep) Validate(config map[string]interface{}) error {
	return nil // No required config
}

func (s *SubfinderStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	domain := resolveDomain(ctx.TargetURL, config)

	args := []string{"-d", domain, "-silent", "-o", "-"}
	if threads, ok := config["threads"]; ok {
		args = append(args, "-t", fmt.Sprint(threads))
	}

	result, err := s.Runner.Run(ctx.Context, RunConfig{
		Name:    "subfinder",
		Binary:  "subfinder",
		Args:    args,
		Timeout: 5 * time.Minute,
	})
	if err != nil {
		return nil, err
	}

	subdomains := parseLines(result.Stdout)

	stepResult := &pipeline.StepResult{
		Name:  "subfinder",
		Hosts: subdomains,
	}
	for _, sub := range subdomains {
		stepResult.Results = append(stepResult.Results, core.Result{
			Type:   "subdomain",
			URL:    sub,
			Source: "subfinder",
			Tool:   "subfinder",
		})
	}

	return stepResult, nil
}
