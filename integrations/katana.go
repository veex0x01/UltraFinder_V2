package integrations

import (
	"fmt"
	"os"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// KatanaStep wraps katana for endpoint/URL extraction via crawling
type KatanaStep struct {
	Runner *ToolRunner
}

func (k *KatanaStep) Name() string           { return "katana" }
func (k *KatanaStep) Description() string    { return "Endpoint extraction via crawling with katana" }
func (k *KatanaStep) Category() string       { return "recon" }
func (k *KatanaStep) RequiredTools() []string { return []string{"katana"} }

func (k *KatanaStep) Validate(config map[string]interface{}) error {
	return nil
}

func (k *KatanaStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Collect live URLs from previous step (httpx output)
	var urls []string
	if targetsFrom, ok := config["targets_from"].(string); ok {
		urls = ctx.GetURLsFromStep(targetsFrom)
	}
	if len(urls) == 0 {
		urls = ctx.DiscoveredURLs.Items()
	}
	if len(urls) == 0 {
		urls = []string{ctx.TargetURL}
	}

	urlFile, err := WriteURLListToTempFile(urls)
	if err != nil {
		return nil, err
	}
	defer os.Remove(urlFile)

	// Build katana args
	args := []string{
		"-list", urlFile,
		"-silent",
		"-no-color",
	}

	// Crawl depth
	depth := getStringConfig(config, "depth", "3")
	args = append(args, "-d", depth)

	// Concurrency
	if threads, ok := config["threads"]; ok {
		args = append(args, "-c", fmt.Sprint(threads))
	} else {
		args = append(args, "-c", "20")
	}

	// Scope — stay within same domain by default
	if _, ok := config["scope"]; ok {
		args = append(args, "-fs", fmt.Sprint(config["scope"]))
	} else {
		args = append(args, "-fs", "dn") // domain name scope
	}

	// Include JS crawling
	if jsMode, ok := config["js_crawl"]; ok && fmt.Sprint(jsMode) == "true" {
		args = append(args, "-jc")
	}

	// Rate limiting
	if rateLimit, ok := config["rate_limit"]; ok {
		args = append(args, "-rl", fmt.Sprint(rateLimit))
	}

	// Known file extensions to exclude (images, fonts, etc.)
	args = append(args, "-ef", "png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3,pdf")

	timeout := 15 * time.Minute
	if t, ok := config["timeout"]; ok {
		if minutes, ok := t.(float64); ok {
			timeout = time.Duration(minutes) * time.Minute
		}
	}

	result, err := k.Runner.Run(ctx.Context, RunConfig{
		Name:    "katana",
		Binary:  "katana",
		Args:    args,
		Timeout: timeout,
	})
	if err != nil {
		return nil, err
	}

	return k.parseKatanaOutput(result.Stdout), nil
}

func (k *KatanaStep) parseKatanaOutput(data []byte) *pipeline.StepResult {
	stepResult := &pipeline.StepResult{
		Name: "katana",
	}

	lines := parseLines(data)
	seen := make(map[string]bool)

	for _, line := range lines {
		url := line
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true

		stepResult.URLs = append(stepResult.URLs, url)
		stepResult.Results = append(stepResult.Results, core.Result{
			Type:   "endpoint",
			URL:    url,
			Source: "katana",
			Tool:   "katana",
		})
	}

	return stepResult
}
