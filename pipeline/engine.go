package pipeline

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/veex0x01/ultrafinder/reporting"
)

// Engine executes pipelines
type Engine struct {
	registry map[string]Step
	logger   *reporting.Logger
}

// NewEngine creates a new pipeline engine
func NewEngine(logger *reporting.Logger) *Engine {
	return &Engine{
		registry: make(map[string]Step),
		logger:   logger,
	}
}

// RegisterStep adds a step type to the registry
func (e *Engine) RegisterStep(step Step) {
	e.registry[step.Name()] = step
}

// GetRegisteredSteps returns all registered step names
func (e *Engine) GetRegisteredSteps() []string {
	var names []string
	for name := range e.registry {
		names = append(names, name)
	}
	return names
}

// LoadPipeline parses a YAML file into a Pipeline
func (e *Engine) LoadPipeline(path string) (*Pipeline, error) {
	return ParsePipelineFile(path)
}

// Run executes a pipeline
func (e *Engine) Run(pipeline *Pipeline, target string) (*PipelineContext, error) {
	ctx := NewPipelineContext(target, e.logger)

	// Merge pipeline variables into context
	for k, v := range pipeline.Variables {
		ctx.Variables[k] = v
	}

	// Build dependency graph
	batches := e.buildTopologicalBatches(pipeline.Steps)

	e.logger.Info("Starting pipeline: %s (%d steps in %d batches)", pipeline.Name, len(pipeline.Steps), len(batches))

	// Signal handling for skipping steps
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	
	// Execute steps in topological order
	for batchIdx, batch := range batches {
		e.logger.Debug("Executing batch %d/%d (%d steps)", batchIdx+1, len(batches), len(batch))

		// Create a cancellable context for this batch
		batchCtx, cancelBatch := context.WithCancel(context.Background())
		ctx.Context = batchCtx

		// Monitor signals
		stopSigMonitor := make(chan struct{})
		go func() {
			select {
			case <-sigChan:
				e.logger.Warn("\n[!] Ctrl+C received. Skipping current batch...")
				cancelBatch() // Cancel current steps
			case <-stopSigMonitor:
				return
			}
		}()

		var wg sync.WaitGroup
		for _, stepDef := range batch {
			wg.Add(1)
			go func(sd StepDefinition) {
				defer wg.Done()
				e.executeStep(ctx, sd)
			}(stepDef)
		}
		wg.Wait()
		
		// Stop monitor
		close(stopSigMonitor)
		cancelBatch() // cleanup

		// If context was cancelled by signal, we should drain the signal channel to reset for next batch?
		// No, `scan` continues. We just want to "proceed to next step".
		// The loop continues automatically.
	}

	e.logger.Success("Pipeline '%s' complete! %d total results in %v",
		pipeline.Name, len(ctx.AllResults), time.Since(ctx.StartTime).Round(time.Second))

	return ctx, nil
}

func (e *Engine) executeStep(ctx *PipelineContext, sd StepDefinition) {
	step, ok := e.registry[sd.Type]
	if !ok {
		e.logger.Error("Step '%s': unknown type '%s' (not registered)", sd.Name, sd.Type)
		return
	}
	
	// Check Condition
	if sd.Condition != "" {
		shouldRun := checkCondition(sd.Condition, ctx.Variables)
		if !shouldRun {
			e.logger.Info("Skipping step '%s' (condition '%s' not met)", sd.Name, sd.Condition)
			ctx.StoreStepOutput(sd.OutputAs, &StepResult{Name: sd.Name, Status: "skipped"})
			return
		}
	}
	
	// Check cancellation
	select {
	case <-ctx.Context.Done():
		e.logger.Warn("Step '%s' skipped due to cancellation", sd.Name)
		return
	default:
	}

	// Check required tools are installed
	for _, tool := range step.RequiredTools() {
		if !isToolInstalled(tool) {
			e.logger.Error("Step '%s' requires '%s' but it is not installed — skipping", sd.Name, tool)
			return
		}
	}

	// Validate config
	if err := step.Validate(sd.Config); err != nil {
		e.logger.Error("Step '%s' validation failed: %v", sd.Name, err)
		return
	}

	// Run step
	e.logger.Info("Running step: %s (type: %s)", sd.Name, sd.Type)
	startTime := time.Now()

	result, err := step.Run(ctx, sd.Config)

	// If result exists, we should store it even if cancelled or errored
	if result != nil {
		result.Duration = time.Since(startTime)
		
		// Mark as partial/cancelled if context is done
		if ctx.Context.Err() != nil {
			result.Status = "cancelled"
			e.logger.Warn("Step '%s' cancelled - saving partial results", sd.Name)
		} else if err != nil {
			result.Status = "failed"
		} else {
			result.Status = "success"
		}

		// Store output
		ctx.StoreStepOutput(sd.OutputAs, result)
		ctx.AddResults(result.Results)
		ctx.AddURLs(result.URLs)
		
		e.logger.Success("Step '%s' complete (status: %s): %d results, %d URLs, %d hosts (%v)",
			sd.Name, result.Status, len(result.Results), len(result.URLs), len(result.Hosts), result.Duration.Round(time.Millisecond))
	}
	
	// Check cancellation again
	if ctx.Context.Err() != nil {
		return 
	}

	if err != nil {
		e.logger.Error("Step '%s' failed: %v", sd.Name, err)
		return
	}
}

// buildTopologicalBatches creates execution batches respecting dependencies
func (e *Engine) buildTopologicalBatches(steps []StepDefinition) [][]StepDefinition {
	// Build adjacency map
	stepMap := make(map[string]StepDefinition)
	for _, s := range steps {
		stepMap[s.Name] = s
	}

	// Track which steps are completed
	completed := make(map[string]bool)
	var batches [][]StepDefinition

	for len(completed) < len(steps) {
		var batch []StepDefinition

		for _, s := range steps {
			if completed[s.Name] {
				continue
			}

			// Check if all dependencies are met
			deps := s.GetDependencies()
			allMet := true
			for _, dep := range deps {
				if !completed[dep] {
					allMet = false
					break
				}
			}

			if allMet {
				batch = append(batch, s)
			}
		}

		if len(batch) == 0 {
			// Circular dependency or unresolvable — add remaining
			e.logger.Warn("Possible circular dependency detected, forcing remaining steps")
			for _, s := range steps {
				if !completed[s.Name] {
					batch = append(batch, s)
				}
			}
		}

		for _, s := range batch {
			completed[s.Name] = true
		}
		batches = append(batches, batch)
	}

	return batches
}

// isToolInstalled checks if an external binary is in PATH
func isToolInstalled(tool string) bool {
	_, err := exec.LookPath(tool)
	return err == nil
}

// IsToolInstalled is the exported version
func IsToolInstalled(tool string) bool {
	return isToolInstalled(tool)
}

// checkCondition evaluates simple "var == value" or "var != value" conditions
func checkCondition(cond string, vars map[string]string) bool {
	// Simple parsing
	// e.g. "$scope != exact"
	parts := strings.Fields(cond)
	if len(parts) != 3 {
		return true // Invalid condition, default to run (or false?)
	}
	
	left := parts[0]
	op := parts[1]
	right := parts[2]
	
	// Resolve variables
	if strings.HasPrefix(left, "$") {
		key := strings.TrimPrefix(left, "$")
		if v, ok := vars[key]; ok {
			left = v
		} else {
			left = "" // missing var
		}
	}
	// Right side might be literal string
	
	switch op {
	case "==":
		return left == right
	case "!=":
		return left != right
	}
	return true
}
