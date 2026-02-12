package integrations

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// InternalCrawlerStep wraps the core.Crawler for deep crawling
type InternalCrawlerStep struct {
	Runner *ToolRunner
}

func (c *InternalCrawlerStep) Name() string           { return "ultrafinder_crawler" }
func (c *InternalCrawlerStep) Description() string    { return "Deep crawling using UltraFinder's internal engine" }
func (c *InternalCrawlerStep) Category() string       { return "recon" }
func (c *InternalCrawlerStep) RequiredTools() []string { return []string{} }

func (c *InternalCrawlerStep) Validate(config map[string]interface{}) error {
	return nil
}

func (c *InternalCrawlerStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Collect live URLs from previous step (httpx/manual_probe output)
	var hosts []string
	if targetsFrom, ok := config["targets_from"].(string); ok {
		// URLs (http://sub.domain.com) are preferred for crawling
		hosts = ctx.GetURLsFromStep(targetsFrom)
		if len(hosts) == 0 {
			hosts = ctx.GetHostsFromStep(targetsFrom)
		}
	}
	if len(hosts) == 0 {
		hosts = ctx.DiscoveredURLs.Items()
	}
	if len(hosts) == 0 {
		hosts = []string{ctx.TargetURL}
	}

	stepResult := &pipeline.StepResult{
		Name: "ultrafinder_crawler",
	}

	hosts = core.Unique(hosts)
	
	if len(hosts) == 0 {
		ctx.Logger.Warn("Crawler: No live hosts/URLs to crawl. Skipping.")
		return &pipeline.StepResult{Name: "ultrafinder_crawler", Status: "skipped"}, nil
	}

	// Crawl each target
	for _, targetURL := range hosts {
		// Check for cancellation
		select {
		case <-ctx.Context.Done():
			ctx.Logger.Warn("Crawler skipped remaining targets due to cancellation")
			return stepResult, nil
		default:
		}

		// Map pipeline config to core.Config
		crawlerConfig := core.Config{
			URL:             targetURL,
			MaxDepth:        getIntConfig(config, "depth", 2),
			Concurrent:      getIntConfig(config, "threads", 10),
			Timeout:         getIntConfig(config, "timeout", 10),
			Delay:           getIntConfig(config, "delay", 0),
			RandomDelay:     getIntConfig(config, "random_delay", 0),
			UserAgent:       getStringConfig(config, "user_agent", ""),
			DisableRedirect: getBoolConfig(config, "disable_redirect", false),
			StealthMode:     getBoolConfig(config, "stealth", false),
			DeepAnalysis:    getBoolConfig(config, "deep_analysis", true),
			IncludeSubs:     getBoolConfig(config, "include_subs", false),
			Verbose:         false, 
			Quiet:           true,  // Suppress banner
			JSONOutput:      true,  // Internal
		}

		// Create temp output file
		tmpFile, _ := os.CreateTemp("", "crawler_out_*.json")
		crawlerConfig.OutputFile = tmpFile.Name()
		tmpFile.Close()
		defer os.Remove(crawlerConfig.OutputFile)

		crawler, err := core.NewCrawler(crawlerConfig)
		if err != nil {
			ctx.Logger.Error("Failed to initialize crawler for %s: %v", targetURL, err)
			continue
		}

		ctx.Logger.Info("Crawling %s...", targetURL)

		// Hook into results
		crawler.SetOutputCallback(func(r core.Result) {
			stepResult.Results = append(stepResult.Results, r)
			if r.Type == "url" || r.Type == "href" || r.Type == "form" || r.Type == "js" {
				if r.URL != "" {
					stepResult.URLs = append(stepResult.URLs, r.URL)
				}
			}
		})

		crawler.Run(ctx.Context)
	}

	// De-duplicate gathered URLs
	stepResult.URLs = core.Unique(stepResult.URLs)

	// Post-processing: Classify and Save
	if len(stepResult.URLs) > 0 {
		if err := c.classifyAndSave(ctx, stepResult.URLs); err != nil {
			ctx.Logger.Error("Failed to save classified results: %v", err)
		}
	}
	
	ctx.Logger.Success("Crawling complete: %d unique endpoints found", len(stepResult.URLs))
	return stepResult, nil
}

// classifyAndSave sorts URLs into categories and writes them to results folders
func (c *InternalCrawlerStep) classifyAndSave(ctx *pipeline.PipelineContext, urls []string) error {
	// Categories
	params := []string{}
	assets := []string{} // js, css
	files := []string{}  // strict files (extensions)
	endpoints := []string{} // rest (paths, no ext)

	for _, u := range urls {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}

		if parsed.RawQuery != "" {
			params = append(params, u)
			// Don't continue, keep valid logic flow
			// Item can be in multiple lists? User implied disjoint lists? 
			// "classify them into txt files... one with params... otherone for sensitive files"
			// If foo.php?id=1, is it param? Yes.
			// Is it also file? Yes (.php).
			// Usually params is more interesting. 
			// I'll put it in params ONLY to avoid dups across files?
			// Or both.
			// Pro-tip: Params are for SQLi/XSS. Files are for sensitive data.
			// I'll make them disjoint for clarity. Priority: Params > Assets > Files > Endpoints.
			continue 
		}

		path := parsed.Path
		ext := strings.ToLower(filepath.Ext(path))

		if ext == ".js" || ext == ".css" {
			assets = append(assets, u)
			continue
		}

		if ext != "" && ext != "/" {
			// It has an extension
			files = append(files, u)
			continue
		}

		endpoints = append(endpoints, u)
	}

	// Output directory
	resultsDir := filepath.Join("results", ctx.TargetDomain)
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return err
	}

	// Write files
	if len(params) > 0 {
		WriteLines(filepath.Join(resultsDir, "params.txt"), params)
	}
	if len(assets) > 0 {
		WriteLines(filepath.Join(resultsDir, "assets.txt"), assets)
	}
	if len(files) > 0 {
		WriteLines(filepath.Join(resultsDir, "files.txt"), files)
	}
	if len(endpoints) > 0 {
		WriteLines(filepath.Join(resultsDir, "endpoints.txt"), endpoints)
	}

	ctx.Logger.Success("Classified results saved to %s/", resultsDir)
	return nil
}

func WriteLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		f.WriteString(l + "\n")
	}
	return nil
}
