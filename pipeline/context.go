package pipeline

import (
	"context"
	"sync"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/reporting"
)

// PipelineContext is shared across all steps in a pipeline run
type PipelineContext struct {
	TargetURL       string
	TargetDomain    string
	DiscoveredURLs  *core.StringSet          // Accumulated URLs from all steps
	DiscoveredHosts *core.StringSet          // Accumulated hosts/subdomains
	AllResults      []core.Result            // All findings from all steps
	Output          *core.Output             // Shared output writer
	Logger          *reporting.Logger        // Structured logger
	Variables       map[string]string        // User-defined variables
	StepOutputs     map[string]*StepResult   // Access previous step output by name
	WorkDir         string                   // Temp working directory for this run
	StartTime       time.Time
	Context         context.Context          // Context for cancellation/skipping
	mu              sync.Mutex
}

// NewPipelineContext creates a new context for a pipeline run
func NewPipelineContext(target string, logger *reporting.Logger) *PipelineContext {
	domain := extractDomain(target)
	return &PipelineContext{
		TargetURL:       target,
		TargetDomain:    domain,
		DiscoveredURLs:  core.NewStringSet(),
		DiscoveredHosts: core.NewStringSet(),
		AllResults:      make([]core.Result, 0),
		Variables:       make(map[string]string),
		StepOutputs:     make(map[string]*StepResult),
		Logger:          logger,
		StartTime:       time.Now(),
		Context:         context.Background(),
	}
}

// AddURLs adds URLs to the context (thread-safe)
func (ctx *PipelineContext) AddURLs(urls []string) {
	for _, u := range urls {
		ctx.DiscoveredURLs.Add(u)
	}
}

// AddResults adds results to the context (thread-safe)
func (ctx *PipelineContext) AddResults(results []core.Result) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.AllResults = append(ctx.AllResults, results...)
}

// StoreStepOutput stores a step's output by name (thread-safe)
func (ctx *PipelineContext) StoreStepOutput(name string, result *StepResult) {
	if name == "" {
		return
	}
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.StepOutputs[name] = result
}

// GetStepOutput retrieves a step's output by name
func (ctx *PipelineContext) GetStepOutput(stepName string) *StepResult {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	return ctx.StepOutputs[stepName]
}

// GetURLsFromStep returns URLs from a named step's output
func (ctx *PipelineContext) GetURLsFromStep(stepName string) []string {
	result := ctx.GetStepOutput(stepName)
	if result == nil {
		return nil
	}
	return result.URLs
}

// GetHostsFromStep returns hosts from a named step's output
func (ctx *PipelineContext) GetHostsFromStep(stepName string) []string {
	result := ctx.GetStepOutput(stepName)
	if result == nil {
		return nil
	}
	return result.Hosts
}

// GetResultsFromStep returns all results from a named step's output
func (ctx *PipelineContext) GetResultsFromStep(stepName string) []core.Result {
	result := ctx.GetStepOutput(stepName)
	if result == nil {
		return nil
	}
	return result.Results
}

// GetAllURLs returns all discovered URLs as a slice
func (ctx *PipelineContext) GetAllURLs() []string {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	var urls []string
	for _, r := range ctx.AllResults {
		if r.URL != "" {
			urls = append(urls, r.URL)
		}
	}
	return core.Unique(urls)
}

// extractDomain extracts the root domain from a URL or hostname
func extractDomain(target string) string {
	// Strip protocol
	domain := target
	for _, prefix := range []string{"https://", "http://"} {
		if len(domain) > len(prefix) && domain[:len(prefix)] == prefix {
			domain = domain[len(prefix):]
			break
		}
	}
	// Strip path
	for i, c := range domain {
		if c == '/' {
			domain = domain[:i]
			break
		}
	}
	// Strip port
	for i, c := range domain {
		if c == ':' {
			domain = domain[:i]
			break
		}
	}
	return domain
}
