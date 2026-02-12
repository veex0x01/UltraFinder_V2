package integrations

import (
	"fmt"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// HttpxStep wraps httpx for live HTTP probing
type HttpxStep struct {
	Runner *ToolRunner
}

func (h *HttpxStep) Name() string           { return "httpx" }
func (h *HttpxStep) Description() string    { return "HTTP probing to filter live hosts via httpx" }
func (h *HttpxStep) Category() string       { return "recon" }
func (h *HttpxStep) RequiredTools() []string { return []string{"httpx"} }

func (h *HttpxStep) Validate(config map[string]interface{}) error {
	return nil
}

func (h *HttpxStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Collect hosts from previous steps (subfinder/amass output)
	var hosts []string

	if targetsFrom, ok := config["targets_from"]; ok {
		// Handle single string
		if single, ok := targetsFrom.(string); ok {
			sHosts := ctx.GetHostsFromStep(single)
			if len(sHosts) == 0 {
				sHosts = ctx.GetURLsFromStep(single)
			}
			hosts = append(hosts, sHosts...)
		}
		// Handle list of strings
		if list, ok := targetsFrom.([]interface{}); ok {
			for _, item := range list {
				if stepName, ok := item.(string); ok {
					sHosts := ctx.GetHostsFromStep(stepName)
					if len(sHosts) == 0 {
						sHosts = ctx.GetURLsFromStep(stepName)
					}
					hosts = append(hosts, sHosts...)
				}
			}
		}
	}

	if len(hosts) == 0 {
		// Fallback: use all discovered hosts
		hosts = ctx.DiscoveredHosts.Items()
	}
	if len(hosts) == 0 {
		hosts = []string{ctx.TargetURL}
	}

	// Deduplicate
	hosts = core.Unique(hosts)

	hostFile, err := WriteURLListToTempFile(hosts)
	if err != nil {
		return nil, err
	}
	// defer os.Remove(hostFile) -- keep for debug if needed

	args := []string{
		"-l", hostFile,
		"-silent",
		"-no-color",
		"-status-code",
		"-title",
		"-tech-detect",
		"-follow-redirects",
	}

	// Filter by status code — only 2xx/3xx (live hosts)
	if mc, ok := config["match_codes"]; ok {
		args = append(args, "-mc", fmt.Sprint(mc))
	} else {
		args = append(args, "-mc", "200,201,204,301,302,303,307,308,401,403")
	}

	if threads, ok := config["threads"]; ok {
		args = append(args, "-threads", fmt.Sprint(threads))
	} else {
		args = append(args, "-threads", "50")
	}

	if rateLimit, ok := config["rate_limit"]; ok {
		args = append(args, "-rl", fmt.Sprint(rateLimit))
	}

	timeout := 10 * time.Minute
	if t, ok := config["timeout"]; ok {
		if minutes, ok := t.(float64); ok {
			timeout = time.Duration(minutes) * time.Minute
		}
	}

	result, err := h.Runner.Run(ctx.Context, RunConfig{
		Name:    "httpx",
		Binary:  "httpx",
		Args:    args,
		Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}

	return h.parseHttpxOutput(result.Stdout), nil
}

func (h *HttpxStep) parseHttpxOutput(data []byte) *pipeline.StepResult {
	stepResult := &pipeline.StepResult{
		Name: "httpx",
	}

	lines := parseLines(data)
	for _, line := range lines {
		// httpx output format: URL [StatusCode] [Title] [Tech]
		// Minimal: just the URL
		urlStr := extractURLFromHttpxLine(line)
		if urlStr == "" {
			continue
		}

		stepResult.URLs = append(stepResult.URLs, urlStr)
		stepResult.Hosts = append(stepResult.Hosts, urlStr)
		stepResult.Results = append(stepResult.Results, core.Result{
			Type:     "live-host",
			URL:      urlStr,
			Source:   "httpx",
			Tool:     "httpx",
			Severity: "INFO",
			Evidence: line, // Full httpx output line with status/title/tech
		})
	}

	return stepResult
}

// extractURLFromHttpxLine extracts the URL from an httpx output line
// Format: "https://example.com [200] [Example Title] [nginx]"
func extractURLFromHttpxLine(line string) string {
	// URL is always the first token before any [bracket]
	for i, c := range line {
		if c == ' ' || c == '[' {
			return line[:i]
		}
	}
	// No brackets — entire line is the URL
	if len(line) > 0 {
		return line
	}
	return ""
}
