package integrations

import (
	"fmt"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// AmassStep wraps Amass for subdomain enumeration
type AmassStep struct {
	Runner *ToolRunner
}

func (a *AmassStep) Name() string        { return "amass" }
func (a *AmassStep) Description() string  { return "Active/passive subdomain enumeration via Amass" }
func (a *AmassStep) Category() string     { return "recon" }
func (a *AmassStep) RequiredTools() []string { return []string{"amass"} }

func (a *AmassStep) Validate(config map[string]interface{}) error {
	return nil
}

func (a *AmassStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	domain := resolveDomain(ctx.TargetURL, config)
	mode := getStringConfig(config, "mode", "passive")

	args := []string{"enum", "-d", domain, "-passive"}
	if mode == "active" {
		args = []string{"enum", "-d", domain, "-active", "-brute"}
	}

	result, err := a.Runner.Run(ctx.Context, RunConfig{
		Name:    "amass",
		Binary:  "amass",
		Args:    args,
		Timeout: 30 * time.Minute,
	})
	if err != nil {
		return nil, err
	}

	subdomains := parseLines(result.Stdout)
	stepResult := &pipeline.StepResult{
		Name:  "amass",
		Hosts: subdomains,
	}
	for _, sub := range subdomains {
		stepResult.Results = append(stepResult.Results, core.Result{
			Type:   "subdomain",
			URL:    sub,
			Source: "amass",
			Tool:   "amass",
		})
	}

	ctx.Logger.Info("Amass found %d subdomains for %s", len(subdomains), domain)
	return stepResult, nil
}

// NmapStep wraps Nmap for port scanning
type NmapStep struct {
	Runner *ToolRunner
}

func (n *NmapStep) Name() string           { return "nmap" }
func (n *NmapStep) Description() string     { return "Port scanning and service detection via Nmap" }
func (n *NmapStep) Category() string        { return "recon" }
func (n *NmapStep) RequiredTools() []string { return []string{"nmap"} }

func (n *NmapStep) Validate(config map[string]interface{}) error {
	return nil
}

func (n *NmapStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Get targets: from previous step or target URL
	var hosts []string
	if targetsFrom, ok := config["targets_from"].(string); ok {
		hosts = ctx.GetHostsFromStep(targetsFrom)
	}
	if len(hosts) == 0 {
		hosts = []string{ctx.TargetDomain}
	}

	ports := getStringConfig(config, "ports", "80,443,8080,8443")

	hostFile, err := WriteURLListToTempFile(hosts)
	if err != nil {
		return nil, err
	}

	args := []string{
		"-iL", hostFile,
		"-p", ports,
		"-sV",
		"--open",
		"-oG", "-", // Greppable output to stdout
	}

	// Add custom flags
	if flags, ok := config["flags"].([]interface{}); ok {
		for _, f := range flags {
			args = append(args, fmt.Sprint(f))
		}
	}

	result, err := n.Runner.Run(ctx.Context, RunConfig{
		Name:    "nmap",
		Binary:  "nmap",
		Args:    args,
		Timeout: 15 * time.Minute,
	})
	if err != nil {
		return nil, err
	}

	// Parse greppable output
	return n.parseGrepOutput(result.Stdout)
}

func (n *NmapStep) parseGrepOutput(data []byte) (*pipeline.StepResult, error) {
	lines := parseLines(data)
	stepResult := &pipeline.StepResult{
		Name: "nmap",
	}

	for _, line := range lines {
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		// Parse "Host: x.x.x.x () Ports: 80/open/tcp//http//..."
		if len(line) > 6 && line[:5] == "Host:" {
			stepResult.Results = append(stepResult.Results, core.Result{
				Type:   "open-port",
				URL:    line,
				Source: "nmap",
				Tool:   "nmap",
			})
		}
	}

	return stepResult, nil
}
