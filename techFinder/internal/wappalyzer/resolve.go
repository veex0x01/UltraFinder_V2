package wappalyzer

import (
	"sort"
	"strconv"
)

type resolvedEntry struct {
	Technology *Technology
	Confidence int
	Version    string
}

// Resolve deduplicates detections, resolves implies/excludes, and produces final output
func (w *Wappalyzer) Resolve(detections []Detection) []ResolvedTechnology {
	resolved := make(map[string]*resolvedEntry)

	for _, d := range detections {
		name := d.Technology.Name
		entry, exists := resolved[name]
		if !exists {
			entry = &resolvedEntry{
				Technology: d.Technology,
			}
			resolved[name] = entry
		}

		entry.Confidence = min100(entry.Confidence + d.Pattern.Confidence)

		if len(d.Version) > len(entry.Version) && len(d.Version) <= 15 {
			n, err := strconv.Atoi(d.Version)
			if err != nil || n < 10000 {
				entry.Version = d.Version
			}
		}
	}

	w.resolveExcludes(resolved)
	w.resolveImplies(resolved)

	results := make([]ResolvedTechnology, 0, len(resolved))
	for _, entry := range resolved {
		var version *string
		if entry.Version != "" {
			v := entry.Version
			version = &v
		}

		var cpe *string
		if entry.Technology.CPE != "" {
			c := entry.Technology.CPE
			cpe = &c
		}

		catNames := make([]string, 0, len(entry.Technology.Categories))
		for _, catID := range entry.Technology.Categories {
			if cat := w.GetCategory(catID); cat != nil {
				catNames = append(catNames, cat.Name)
			}
		}

		results = append(results, ResolvedTechnology{
			Name:       entry.Technology.Name,
			Version:    version,
			Confidence: entry.Confidence,
			CPE:        cpe,
			Categories: catNames,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		pi := w.categoryPriority(resolved[results[i].Name].Technology)
		pj := w.categoryPriority(resolved[results[j].Name].Technology)
		return pi < pj
	})

	return results
}

func (w *Wappalyzer) resolveExcludes(resolved map[string]*resolvedEntry) {
	for _, entry := range resolved {
		for _, excludeName := range entry.Technology.Excludes {
			delete(resolved, excludeName)
		}
	}
}

func (w *Wappalyzer) resolveImplies(resolved map[string]*resolvedEntry) {
	for {
		done := true
		for _, entry := range resolved {
			for _, impl := range entry.Technology.Implies {
				if _, exists := resolved[impl.Name]; exists {
					continue
				}

				implied := w.GetTechnology(impl.Name)
				if implied == nil {
					continue
				}

				resolved[impl.Name] = &resolvedEntry{
					Technology: implied,
					Confidence: min100(min(entry.Confidence, impl.Confidence)),
					Version:    "",
				}
				done = false
			}
		}
		if done {
			break
		}
	}
}

// ProcessRequires checks if detected technologies trigger requires groups
// and runs additional analysis for conditional technologies
func (w *Wappalyzer) ProcessRequires(detections []Detection, data *PageData) []Detection {
	resolvedNames := make(map[string]bool)
	resolvedCats := make(map[int]bool)

	tempResolved := w.Resolve(detections)
	for _, r := range tempResolved {
		resolvedNames[r.Name] = true
		if entry, ok := w.techByName[r.Name]; ok {
			for _, catID := range entry.Categories {
				resolvedCats[catID] = true
			}
		}
	}

	var additionalTechs []*Technology

	for _, rg := range w.Requires {
		if resolvedNames[rg.Name] {
			additionalTechs = append(additionalTechs, rg.Technologies...)
		}
	}

	for _, rg := range w.CategoryRequires {
		if resolvedCats[rg.CategoryID] {
			additionalTechs = append(additionalTechs, rg.Technologies...)
		}
	}

	if len(additionalTechs) > 0 {
		extra := w.Analyze(data, additionalTechs)
		detections = append(detections, extra...)
	}

	return detections
}

func (w *Wappalyzer) categoryPriority(tech *Technology) int {
	maxPriority := 0
	for _, catID := range tech.Categories {
		if cat := w.GetCategory(catID); cat != nil {
			if cat.Priority > maxPriority {
				maxPriority = cat.Priority
			}
		}
	}
	return maxPriority
}

func min100(n int) int {
	if n > 100 {
		return 100
	}
	return n
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
