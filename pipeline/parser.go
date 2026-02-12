package pipeline

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Pipeline represents a parsed pipeline definition
type Pipeline struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Version     string            `yaml:"version"`
	Author      string            `yaml:"author"`
	Variables   map[string]string `yaml:"variables,omitempty"`
	Steps       []StepDefinition  `yaml:"steps"`
}

// ParsePipelineFile reads and parses a YAML pipeline file
func ParsePipelineFile(path string) (*Pipeline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read pipeline file %s: %w", path, err)
	}
	return ParsePipeline(data)
}

// ParsePipeline parses YAML bytes into a Pipeline
func ParsePipeline(data []byte) (*Pipeline, error) {
	var p Pipeline
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to parse pipeline YAML: %w", err)
	}

	if len(p.Steps) == 0 {
		return nil, fmt.Errorf("pipeline has no steps defined")
	}

	// Validate step names are unique
	seen := make(map[string]bool)
	for _, step := range p.Steps {
		if step.Name == "" {
			return nil, fmt.Errorf("step missing required 'name' field")
		}
		if step.Type == "" {
			return nil, fmt.Errorf("step '%s' missing required 'type' field", step.Name)
		}
		if seen[step.Name] {
			return nil, fmt.Errorf("duplicate step name: %s", step.Name)
		}
		seen[step.Name] = true
	}

	return &p, nil
}

// ListPipelineFiles lists all YAML pipeline files in a directory
func ListPipelineFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) > 5 && (name[len(name)-5:] == ".yaml" || name[len(name)-4:] == ".yml") {
			files = append(files, name)
		}
	}
	return files, nil
}
