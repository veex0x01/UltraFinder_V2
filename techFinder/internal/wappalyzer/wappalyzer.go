package wappalyzer

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

//go:embed technologies/*.json
var techFS embed.FS

//go:embed categories.json
var categoriesData []byte

// Wappalyzer holds all loaded technologies and categories
type Wappalyzer struct {
	Technologies     []*Technology
	Categories       map[int]*Category
	Requires         []RequiresGroup
	CategoryRequires []RequiresGroup
	techByName       map[string]*Technology
}

// New loads all technology fingerprints and categories
func New() (*Wappalyzer, error) {
	w := &Wappalyzer{
		Categories: make(map[int]*Category),
		techByName: make(map[string]*Technology),
	}

	if err := w.loadCategories(); err != nil {
		return nil, fmt.Errorf("loading categories: %w", err)
	}

	for i := 0; i < 27; i++ {
		var char string
		if i == 0 {
			char = "_"
		} else {
			char = string(rune('a' + i - 1))
		}
		filename := fmt.Sprintf("technologies/%s.json", char)
		data, err := techFS.ReadFile(filename)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", filename, err)
		}

		var raw map[string]RawTechnology
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", filename, err)
		}

		for name, rt := range raw {
			tech := w.parseTechnology(name, &rt)
			w.techByName[name] = tech
		}
	}

	w.buildRequiresGroups()

	return w, nil
}

// GetTechnology looks up a technology by name
func (w *Wappalyzer) GetTechnology(name string) *Technology {
	return w.techByName[name]
}

// GetCategory looks up a category by ID
func (w *Wappalyzer) GetCategory(id int) *Category {
	return w.Categories[id]
}

func (w *Wappalyzer) loadCategories() error {
	var raw map[string]Category
	if err := json.Unmarshal(categoriesData, &raw); err != nil {
		return err
	}

	for idStr, cat := range raw {
		id, err := strconv.Atoi(idStr)
		if err != nil {
			continue
		}
		cat.ID = id
		cat.Slug = slugify(cat.Name)
		c := cat
		w.Categories[id] = &c
	}

	return nil
}

func (w *Wappalyzer) parseTechnology(name string, raw *RawTechnology) *Technology {
	tech := &Technology{
		Name:        name,
		Description: raw.Description,
		Slug:        slugify(name),
		Categories:  raw.Cats,
		Icon:        raw.Icon,
		Website:     raw.Website,
		Pricing:     raw.Pricing,
		CPE:         raw.CPE,
	}

	if tech.Icon == "" {
		tech.Icon = "default.svg"
	}
	if tech.Categories == nil {
		tech.Categories = []int{}
	}

	tech.URL = toPatternSlice(raw.URL, true)
	tech.XHR = toPatternSlice(raw.XHR, true)
	tech.HTML = toPatternSlice(raw.HTML, true)
	tech.Text = toPatternSlice(raw.Text, true)
	tech.Scripts = toPatternSlice(raw.Scripts, true)
	tech.CSS = toPatternSlice(raw.CSS, true)
	tech.Robots = toPatternSlice(raw.Robots, true)
	tech.Magento = toPatternSlice(raw.Magento, true)
	tech.CertIssuer = toPatternSlice(raw.CertIssuer, true)
	tech.ScriptSrc = toPatternSlice(raw.ScriptSrc, true)

	tech.Headers = toPatternMap(raw.Headers, false, true)
	tech.Cookies = toPatternMap(raw.Cookies, false, true)
	tech.Meta = toPatternMap(raw.Meta, false, true)
	tech.DNS = toPatternMap(raw.DNS, false, true)
	tech.JS = toPatternMap(raw.JS, true, true)

	tech.Dom = parseDom(raw.Dom)

	tech.Implies = parseImplies(raw.Implies)
	tech.Excludes = parseExcludes(raw.Excludes)
	tech.Requires = parseExcludes(raw.Requires)
	tech.RequiresCategory = toIntSlice(raw.RequiresCategory)

	if tech.Implies == nil {
		tech.Implies = []ImpliesEntry{}
	}
	if tech.Excludes == nil {
		tech.Excludes = []string{}
	}
	if tech.Requires == nil {
		tech.Requires = []string{}
	}
	if tech.RequiresCategory == nil {
		tech.RequiresCategory = []int{}
	}

	return tech
}

func parseDom(v interface{}) map[string][]DomRule {
	if v == nil {
		return nil
	}

	result := make(map[string][]DomRule)

	switch val := v.(type) {
	case string:
		result[val] = []DomRule{{Exists: true}}
	case []interface{}:
		for _, item := range val {
			if s, ok := item.(string); ok {
				result[s] = []DomRule{{Exists: true}}
			}
		}
	case map[string]interface{}:
		for selector, rules := range val {
			domRules := parseDomRules(rules)
			result[selector] = domRules
		}
	}

	return result
}

func parseDomRules(v interface{}) []DomRule {
	ruleMap, ok := v.(map[string]interface{})
	if !ok {
		return []DomRule{{Exists: true}}
	}

	rule := DomRule{}

	if _, ok := ruleMap["exists"]; ok {
		rule.Exists = true
	}

	if textVal, ok := ruleMap["text"]; ok {
		if s, ok := textVal.(string); ok {
			p := ParsePattern(s, true)
			rule.Text = &p
		}
	}

	if propsVal, ok := ruleMap["properties"]; ok {
		if props, ok := propsVal.(map[string]interface{}); ok {
			rule.Properties = make(map[string]*Pattern)
			for prop, pv := range props {
				s := fmt.Sprint(pv)
				p := ParsePattern(s, true)
				rule.Properties[prop] = &p
			}
		}
	}

	if attrsVal, ok := ruleMap["attributes"]; ok {
		if attrs, ok := attrsVal.(map[string]interface{}); ok {
			rule.Attributes = make(map[string]*Pattern)
			for attr, av := range attrs {
				s := fmt.Sprint(av)
				p := ParsePattern(s, true)
				rule.Attributes[attr] = &p
			}
		}
	}

	return []DomRule{rule}
}

func (w *Wappalyzer) buildRequiresGroups() {
	requiresMap := make(map[string][]*Technology)
	categoryRequiresMap := make(map[int][]*Technology)

	var mainTechs []*Technology

	for _, tech := range w.techByName {
		if len(tech.Requires) > 0 || len(tech.RequiresCategory) > 0 {
			for _, reqName := range tech.Requires {
				if w.techByName[reqName] == nil {
					continue
				}
				requiresMap[reqName] = append(requiresMap[reqName], tech)
			}
			for _, catID := range tech.RequiresCategory {
				categoryRequiresMap[catID] = append(categoryRequiresMap[catID], tech)
			}
		} else {
			mainTechs = append(mainTechs, tech)
		}
	}

	w.Technologies = mainTechs

	for name, techs := range requiresMap {
		w.Requires = append(w.Requires, RequiresGroup{
			Name:         name,
			Technologies: techs,
		})
	}

	for catID, techs := range categoryRequiresMap {
		w.CategoryRequires = append(w.CategoryRequires, RequiresGroup{
			CategoryID:   catID,
			Technologies: techs,
		})
	}
}

var slugifyRe = regexp.MustCompile(`[^a-z0-9-]`)
var slugifyDash = regexp.MustCompile(`--+`)

func slugify(s string) string {
	result := strings.ToLower(s)
	result = slugifyRe.ReplaceAllString(result, "-")
	result = slugifyDash.ReplaceAllString(result, "-")
	result = strings.Trim(result, "-")
	return result
}
