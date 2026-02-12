package wappalyzer

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ParsePattern parses a raw pattern string like "regex\\;version:\\1\\;confidence:50"
func ParsePattern(raw string, isRegex bool) Pattern {
	p := Pattern{
		Confidence: 100,
	}

	str := fmt.Sprint(raw)
	parts := strings.Split(str, "\\;")

	p.Value = parts[0]

	if isRegex && len(parts[0]) > 0 {
		regexStr := parts[0]
		regexStr = strings.ReplaceAll(regexStr, "/", "\\/")
		regexStr = strings.ReplaceAll(regexStr, "+", "{1,250}")
		regexStr = strings.ReplaceAll(regexStr, "*", "{0,250}")

		compiled, err := regexp.Compile("(?i)" + regexStr)
		if err != nil {
			compiled = regexp.MustCompile("(?i)")
		}
		p.Regex = compiled
	} else {
		p.Regex = regexp.MustCompile("(?i)")
	}

	for _, part := range parts[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			switch kv[0] {
			case "version":
				p.Version = kv[1]
			case "confidence":
				if n, err := strconv.Atoi(kv[1]); err == nil {
					p.Confidence = n
				}
			}
		}
	}

	return p
}

// ResolveVersion substitutes backreferences (\\1, \\2) and ternary operators in version templates
func ResolveVersion(p Pattern, value string) string {
	if p.Version == "" {
		return ""
	}

	resolved := p.Version
	matches := p.Regex.FindStringSubmatch(value)
	if matches == nil {
		return resolved
	}

	for i, match := range matches {
		ternaryRe := regexp.MustCompile(fmt.Sprintf(`\\%d\?([^:]+):(.*)$`, i))
		if ternaryMatch := ternaryRe.FindStringSubmatch(resolved); len(ternaryMatch) == 3 {
			replacement := ternaryMatch[2]
			if match != "" {
				replacement = ternaryMatch[1]
			}
			resolved = strings.Replace(resolved, ternaryMatch[0], replacement, 1)
		}

		resolved = strings.ReplaceAll(resolved, fmt.Sprintf("\\%d", i), match)
	}

	return strings.TrimSpace(resolved)
}

// toStringSlice normalizes interface{} -> []string
func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return []string{val}
	case float64:
		return []string{fmt.Sprintf("%v", val)}
	case int:
		return []string{fmt.Sprintf("%d", val)}
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			switch s := item.(type) {
			case string:
				result = append(result, s)
			case float64:
				result = append(result, fmt.Sprintf("%v", s))
			}
		}
		return result
	}
	return nil
}

// toPatternSlice normalizes interface{} -> []Pattern
func toPatternSlice(v interface{}, isRegex bool) []Pattern {
	strs := toStringSlice(v)
	if strs == nil {
		return nil
	}
	patterns := make([]Pattern, 0, len(strs))
	for _, s := range strs {
		patterns = append(patterns, ParsePattern(s, isRegex))
	}
	return patterns
}

// toPatternMap normalizes a map[string]interface{} -> map[string][]Pattern
func toPatternMap(v map[string]interface{}, caseSensitive bool, isRegex bool) map[string][]Pattern {
	if v == nil {
		return nil
	}
	result := make(map[string][]Pattern)
	for key, val := range v {
		k := key
		if !caseSensitive {
			k = strings.ToLower(key)
		}
		strs := toStringSlice(val)
		if strs == nil {
			strs = []string{fmt.Sprint(val)}
		}
		patterns := make([]Pattern, 0, len(strs))
		for _, s := range strs {
			patterns = append(patterns, ParsePattern(s, isRegex))
		}
		result[k] = patterns
	}
	return result
}

// toIntSlice normalizes interface{} -> []int
func toIntSlice(v interface{}) []int {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case float64:
		return []int{int(val)}
	case int:
		return []int{val}
	case []interface{}:
		result := make([]int, 0, len(val))
		for _, item := range val {
			switch n := item.(type) {
			case float64:
				result = append(result, int(n))
			case int:
				result = append(result, n)
			}
		}
		return result
	}
	return nil
}

// parseImplies parses implies entries with optional confidence
func parseImplies(v interface{}) []ImpliesEntry {
	strs := toStringSlice(v)
	if strs == nil {
		return nil
	}
	entries := make([]ImpliesEntry, 0, len(strs))
	for _, s := range strs {
		p := ParsePattern(s, false)
		entries = append(entries, ImpliesEntry{
			Name:       p.Value,
			Confidence: p.Confidence,
		})
	}
	return entries
}

// parseExcludes parses excludes entries
func parseExcludes(v interface{}) []string {
	strs := toStringSlice(v)
	if strs == nil {
		return nil
	}
	result := make([]string, 0, len(strs))
	for _, s := range strs {
		p := ParsePattern(s, false)
		result = append(result, p.Value)
	}
	return result
}
