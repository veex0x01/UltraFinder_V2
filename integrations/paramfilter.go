package integrations

import (
	"net/url"
	"strings"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline"
)

// ParamFilterStep filters URLs to only those containing query parameters
// This is a pure Go step — no external tool required
type ParamFilterStep struct{}

func (p *ParamFilterStep) Name() string           { return "paramfilter" }
func (p *ParamFilterStep) Description() string    { return "Filter URLs to only those with query parameters" }
func (p *ParamFilterStep) Category() string       { return "filter" }
func (p *ParamFilterStep) RequiredTools() []string { return []string{} }

func (p *ParamFilterStep) Validate(config map[string]interface{}) error {
	return nil
}

func (p *ParamFilterStep) Run(ctx *pipeline.PipelineContext, config map[string]interface{}) (*pipeline.StepResult, error) {
	// Collect URLs from previous step (katana output)
	var urls []string
	if targetsFrom, ok := config["targets_from"].(string); ok {
		urls = ctx.GetURLsFromStep(targetsFrom)
	}
	if len(urls) == 0 {
		urls = ctx.DiscoveredURLs.Items()
	}

	stepResult := &pipeline.StepResult{
		Name: "paramfilter",
	}

	seen := make(map[string]bool)

	for _, rawURL := range urls {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			continue
		}

		// Must have query parameters
		if len(parsed.Query()) == 0 {
			continue
		}

		// Deduplicate by base URL + param names (ignore values for dedup)
		paramKey := normalizeURLParams(parsed)
		if seen[paramKey] {
			continue
		}
		seen[paramKey] = true

		stepResult.URLs = append(stepResult.URLs, rawURL)
		stepResult.Results = append(stepResult.Results, core.Result{
			Type:      "parameterized-url",
			URL:       rawURL,
			Source:    "paramfilter",
			Tool:      "paramfilter",
			Parameter: extractParamNames(parsed),
		})
	}

	return stepResult, nil
}

// normalizeURLParams creates a dedup key: scheme+host+path+sorted param names
func normalizeURLParams(u *url.URL) string {
	params := u.Query()
	var paramNames []string
	for k := range params {
		paramNames = append(paramNames, k)
	}
	// Sort for consistent dedup
	sortStrings(paramNames)
	return u.Scheme + "://" + u.Host + u.Path + "?" + strings.Join(paramNames, "&")
}

// extractParamNames returns comma-separated parameter names
func extractParamNames(u *url.URL) string {
	params := u.Query()
	var names []string
	for k := range params {
		names = append(names, k)
	}
	return strings.Join(names, ",")
}

// sortStrings is a simple insertion sort for small slices
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && s[j] > key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}
