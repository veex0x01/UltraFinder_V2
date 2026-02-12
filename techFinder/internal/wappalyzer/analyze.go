package wappalyzer

import (
	"fmt"
	"regexp"
)

// Analyze runs all pattern types against extracted page data
func (w *Wappalyzer) Analyze(data *PageData, techs []*Technology) []Detection {
	if techs == nil {
		techs = w.Technologies
	}

	var detections []Detection

	for _, tech := range techs {
		// oneToOne: pattern(s) tested against a single string
		if data.URL != "" {
			detections = append(detections, analyzeOneToOne(tech, tech.URL, "url", data.URL)...)
		}
		if data.HTML != "" {
			detections = append(detections, analyzeOneToOne(tech, tech.HTML, "html", data.HTML)...)
		}
		if data.Text != "" {
			detections = append(detections, analyzeOneToOne(tech, tech.Text, "text", data.Text)...)
		}
		if data.Scripts != "" {
			detections = append(detections, analyzeOneToOne(tech, tech.Scripts, "scripts", data.Scripts)...)
		}
		if data.CSS != "" {
			detections = append(detections, analyzeOneToOne(tech, tech.CSS, "css", data.CSS)...)
		}
		if data.Robots != "" {
			detections = append(detections, analyzeOneToOne(tech, tech.Robots, "robots", data.Robots)...)
		}
		if data.Magento != "" {
			detections = append(detections, analyzeOneToOne(tech, tech.Magento, "magento", data.Magento)...)
		}
		if data.CertIssuer != "" {
			detections = append(detections, analyzeOneToOne(tech, tech.CertIssuer, "certIssuer", data.CertIssuer)...)
		}

		// oneToMany: each item tested against all patterns
		if len(data.ScriptSrc) > 0 {
			detections = append(detections, analyzeOneToMany(tech, tech.ScriptSrc, "scriptSrc", data.ScriptSrc)...)
		}

		// manyToMany: keyed patterns against keyed values
		if len(data.Cookies) > 0 {
			detections = append(detections, analyzeManyToMany(tech, tech.Cookies, "cookies", data.Cookies)...)
		}
		if len(data.Meta) > 0 {
			detections = append(detections, analyzeManyToMany(tech, tech.Meta, "meta", data.Meta)...)
		}
		if len(data.Headers) > 0 {
			detections = append(detections, analyzeManyToMany(tech, tech.Headers, "headers", data.Headers)...)
		}
		if len(data.DNS) > 0 {
			detections = append(detections, analyzeManyToMany(tech, tech.DNS, "dns", data.DNS)...)
		}
	}

	return detections
}

// AnalyzeXHR analyzes XHR hostnames one by one
func (w *Wappalyzer) AnalyzeXHR(hostnames []string, techs []*Technology) []Detection {
	if techs == nil {
		techs = w.Technologies
	}

	var detections []Detection
	for _, hostname := range hostnames {
		for _, tech := range techs {
			detections = append(detections, analyzeOneToOne(tech, tech.XHR, "xhr", hostname)...)
		}
	}
	return detections
}

// AnalyzeJS matches JS global detection results
func (w *Wappalyzer) AnalyzeJS(results []JSResult, techs []*Technology) []Detection {
	if techs == nil {
		techs = w.Technologies
	}

	var detections []Detection
	for _, r := range results {
		for _, tech := range techs {
			if tech.Name != r.Name {
				continue
			}
			valueStr := fmt.Sprint(r.Value)
			items := map[string][]string{
				r.Chain: {valueStr},
			}
			detections = append(detections, analyzeManyToMany(tech, tech.JS, "js", items)...)
		}
	}
	return detections
}

// AnalyzeDOM matches DOM detection results
func (w *Wappalyzer) AnalyzeDOM(results []DOMResult, techs []*Technology) []Detection {
	if techs == nil {
		techs = w.Technologies
	}

	var detections []Detection
	for _, r := range results {
		for _, tech := range techs {
			if tech.Name != r.Name {
				continue
			}

			if r.Exists != "" || (r.Text == "" && r.Property == "" && r.Attribute == "") {
				// exists check
				items := map[string][]string{r.Selector: {""}}
				detections = append(detections, analyzeDomSubtype(tech, "dom.exists", items)...)
			}

			if r.Text != "" {
				items := map[string][]string{r.Selector: {r.Text}}
				detections = append(detections, analyzeDomSubtype(tech, "dom.text", items)...)
			}

			if r.Property != "" {
				items := map[string][]string{r.Selector: {r.Value}}
				detections = append(detections, analyzeDomSubtype(tech, "dom.properties."+r.Property, items)...)
			}

			if r.Attribute != "" {
				items := map[string][]string{r.Selector: {r.Value}}
				detections = append(detections, analyzeDomSubtype(tech, "dom.attributes."+r.Attribute, items)...)
			}
		}
	}
	return detections
}

func analyzeDomSubtype(tech *Technology, typePath string, items map[string][]string) []Detection {
	if tech.Dom == nil {
		return nil
	}

	var detections []Detection
	for selector, values := range items {
		rules, ok := tech.Dom[selector]
		if !ok {
			continue
		}

		for _, rule := range rules {
			for _, value := range values {
				var p *Pattern

				switch {
				case typePath == "dom.exists" && rule.Exists:
					emptyP := Pattern{Regex: emptyRegex, Confidence: 100}
					p = &emptyP
				case typePath == "dom.text" && rule.Text != nil:
					p = rule.Text
				case len(typePath) > len("dom.properties.") && typePath[:len("dom.properties.")] == "dom.properties.":
					propName := typePath[len("dom.properties."):]
					if rule.Properties != nil {
						p = rule.Properties[propName]
					}
				case len(typePath) > len("dom.attributes.") && typePath[:len("dom.attributes.")] == "dom.attributes.":
					attrName := typePath[len("dom.attributes."):]
					if rule.Attributes != nil {
						p = rule.Attributes[attrName]
					}
				}

				if p == nil {
					continue
				}

				if loc := p.Regex.FindString(value); loc != "" || (typePath == "dom.exists" && rule.Exists) {
					detections = append(detections, Detection{
						Technology: tech,
						Pattern: MatchedPattern{
							Type:       "dom",
							Value:      value,
							Match:      loc,
							Confidence: p.Confidence,
							Version:    p.Version,
						},
						Version: ResolveVersion(*p, value),
					})
				}
			}
		}
	}
	return detections
}

// analyzeOneToOne: each pattern tested against a single string value
func analyzeOneToOne(tech *Technology, patterns []Pattern, typeName string, value string) []Detection {
	var detections []Detection
	for _, p := range patterns {
		if loc := p.Regex.FindString(value); loc != "" {
			detections = append(detections, Detection{
				Technology: tech,
				Pattern: MatchedPattern{
					Type:       typeName,
					Value:      value,
					Match:      loc,
					Confidence: p.Confidence,
					Version:    p.Version,
				},
				Version: ResolveVersion(p, value),
			})
		}
	}
	return detections
}

// analyzeOneToMany: each pattern tested against each item in a []string
func analyzeOneToMany(tech *Technology, patterns []Pattern, typeName string, items []string) []Detection {
	var detections []Detection
	for _, value := range items {
		for _, p := range patterns {
			if loc := p.Regex.FindString(value); loc != "" {
				detections = append(detections, Detection{
					Technology: tech,
					Pattern: MatchedPattern{
						Type:       typeName,
						Value:      value,
						Match:      loc,
						Confidence: p.Confidence,
						Version:    p.Version,
					},
					Version: ResolveVersion(p, value),
				})
			}
		}
	}
	return detections
}

// analyzeManyToMany: keyed patterns against keyed values
func analyzeManyToMany(tech *Technology, patternMap map[string][]Pattern, typeName string, items map[string][]string) []Detection {
	if patternMap == nil {
		return nil
	}
	var detections []Detection
	for key, patterns := range patternMap {
		values, ok := items[key]
		if !ok {
			continue
		}
		for _, p := range patterns {
			for _, value := range values {
				if loc := p.Regex.FindString(value); loc != "" {
					detections = append(detections, Detection{
						Technology: tech,
						Pattern: MatchedPattern{
							Type:       typeName,
							Value:      value,
							Match:      loc,
							Confidence: p.Confidence,
							Version:    p.Version,
						},
						Version: ResolveVersion(p, value),
					})
				}
			}
		}
	}
	return detections
}

var emptyRegex = func() *regexp.Regexp {
	r, _ := regexp.Compile("(?i)")
	return r
}()
