package integrations

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/veex0x01/ultrafinder/reporting"
)

// ToolRunner runs external tool binaries
type ToolRunner struct {
	Logger *reporting.Logger
}

// RunConfig holds configuration for running an external tool
type RunConfig struct {
	Name       string        // Tool name for logging
	Binary     string        // Binary path
	Args       []string      // Command-line arguments
	Stdin      io.Reader     // Optional stdin input
	Timeout    time.Duration // Max execution time
	WorkDir    string        // Working directory
	Env        []string      // Additional environment variables
	StreamOutput bool          // Stream output to stdout/stderr
}

// RunResult holds the output of an external tool
type RunResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// NewToolRunner creates a new ToolRunner
func NewToolRunner(logger *reporting.Logger) *ToolRunner {
	return &ToolRunner{Logger: logger}
}

// Run executes an external tool
func (r *ToolRunner) Run(ctx context.Context, config RunConfig) (*RunResult, error) {
	// Check binary exists
	binaryPath, err := exec.LookPath(config.Binary)
	if err != nil {
		return nil, fmt.Errorf("%s not found in PATH: %w", config.Binary, err)
	}

	if config.Timeout == 0 {
		config.Timeout = 10 * time.Minute
	}

	// Use parent context (for cancellation) + timeout
	ctx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath, config.Args...)

	var stdout, stderr bytes.Buffer
	
	if config.StreamOutput {
		cmd.Stdout = io.MultiWriter(&stdout, os.Stdout)
		cmd.Stderr = io.MultiWriter(&stderr, os.Stderr)
	} else {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}

	if config.Stdin != nil {
		cmd.Stdin = config.Stdin
	}
	if config.WorkDir != "" {
		cmd.Dir = config.WorkDir
	}
	if len(config.Env) > 0 {
		cmd.Env = append(os.Environ(), config.Env...)
	}

	if r.Logger != nil {
		r.Logger.Debug("[%s] Running: %s %s", config.Name, config.Binary, strings.Join(config.Args, " "))
	}

	startTime := time.Now()
	err = cmd.Run()
	duration := time.Since(startTime)

	result := &RunResult{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		Duration: duration,
	}

	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return result, fmt.Errorf("%s timed out after %v", config.Name, config.Timeout)
		}
		// Non-zero exit is common for scanning tools, log but don't fail
		if r.Logger != nil {
			r.Logger.Debug("[%s] Exit code: %d, stderr: %s", config.Name, result.ExitCode, string(result.Stderr))
		}
	}

	if r.Logger != nil {
		r.Logger.Debug("[%s] Completed in %v (exit: %d, stdout: %d bytes)",
			config.Name, duration.Round(time.Millisecond), result.ExitCode, len(result.Stdout))
	}

	return result, nil
}

// CheckInstalled verifies a tool binary is available
func (r *ToolRunner) CheckInstalled(binary string) (string, error) {
	path, err := exec.LookPath(binary)
	return path, err
}

// WriteURLListToTempFile writes URLs to a temp file for tools that need file input
func WriteURLListToTempFile(urls []string) (string, error) {
	f, err := os.CreateTemp("", "ultrafinder-urls-*.txt")
	if err != nil {
		return "", err
	}

	for _, u := range urls {
		fmt.Fprintln(f, u)
	}
	f.Close()
	return f.Name(), nil
}

// parseLines splits output bytes into non-empty lines
func parseLines(data []byte) []string {
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// getStringConfig extracts a string config value with default
func getStringConfig(config map[string]interface{}, key, defaultVal string) string {
	if v, ok := config[key]; ok {
		return fmt.Sprint(v)
	}
	return defaultVal
}

// resolveDomain extracts domain from context or config
func resolveDomain(targetURL string, config map[string]interface{}) string {
	if d, ok := config["domain"]; ok {
		return fmt.Sprint(d)
	}
	
	// Handle raw domain input (no protocol)
	if !strings.Contains(targetURL, "://") {
		// Try parsing as http://target to extract hostname
		parsed, err := url.Parse("http://" + targetURL)
		if err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
		return targetURL
	}

	// Extract from URL
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return targetURL
	}
	return parsed.Hostname()
}

// Helpers for config extraction
func getIntConfig(config map[string]interface{}, key string, defaultVal int) int {
	if v, ok := config[key]; ok {
		if i, ok := v.(int); ok {
			return i
		}
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return defaultVal
}

func getBoolConfig(config map[string]interface{}, key string, defaultVal bool) bool {
	if v, ok := config[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return defaultVal
}

// hasQueryParams checks if a URL has query parameters
func hasQueryParams(urlStr string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return len(parsed.Query()) > 0
}

// hasMatchingParam checks if a URL contains any of the given parameter names
func hasMatchingParam(urlStr string, params []string) bool {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	query := parsed.Query()
	for param := range query {
		lowerParam := strings.ToLower(param)
		for _, p := range params {
			if strings.Contains(lowerParam, p) {
				return true
			}
		}
	}
	return false
}
