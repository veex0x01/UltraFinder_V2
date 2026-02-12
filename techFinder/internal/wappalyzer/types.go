package wappalyzer

import "regexp"

// RawTechnology matches the JSON schema of each entry in technologies/*.json.
// Uses interface{} for polymorphic fields (string, []string, map, etc.)
type RawTechnology struct {
	Cats             []int                  `json:"cats"`
	Description      string                 `json:"description"`
	URL              interface{}            `json:"url"`
	XHR              interface{}            `json:"xhr"`
	HTML             interface{}            `json:"html"`
	Text             interface{}            `json:"text"`
	Scripts          interface{}            `json:"scripts"`
	CSS              interface{}            `json:"css"`
	Robots           interface{}            `json:"robots"`
	Magento          interface{}            `json:"magento"`
	CertIssuer       interface{}            `json:"certIssuer"`
	ScriptSrc        interface{}            `json:"scriptSrc"`
	Headers          map[string]interface{} `json:"headers"`
	Cookies          map[string]interface{} `json:"cookies"`
	Meta             map[string]interface{} `json:"meta"`
	DNS              map[string]interface{} `json:"dns"`
	JS               map[string]interface{} `json:"js"`
	Dom              interface{}            `json:"dom"`
	Implies          interface{}            `json:"implies"`
	Excludes         interface{}            `json:"excludes"`
	Requires         interface{}            `json:"requires"`
	RequiresCategory interface{}            `json:"requiresCategory"`
	Icon             string                 `json:"icon"`
	Website          string                 `json:"website"`
	Pricing          []string               `json:"pricing"`
	CPE              string                 `json:"cpe"`
}

// Pattern is the compiled form of a single pattern string after \\; splitting
type Pattern struct {
	Value      string
	Regex      *regexp.Regexp
	Confidence int
	Version    string
}

// Technology is the fully parsed representation of a technology fingerprint
type Technology struct {
	Name             string
	Description      string
	Slug             string
	Categories       []int
	URL              []Pattern
	XHR              []Pattern
	HTML             []Pattern
	Text             []Pattern
	Scripts          []Pattern
	CSS              []Pattern
	Robots           []Pattern
	Magento          []Pattern
	CertIssuer       []Pattern
	ScriptSrc        []Pattern
	Headers          map[string][]Pattern
	Cookies          map[string][]Pattern
	Meta             map[string][]Pattern
	DNS              map[string][]Pattern
	JS               map[string][]Pattern
	Dom              map[string][]DomRule
	Implies          []ImpliesEntry
	Excludes         []string
	Requires         []string
	RequiresCategory []int
	Icon             string
	Website          string
	Pricing          []string
	CPE              string
}

// DomRule represents matching rules for a given CSS selector
type DomRule struct {
	Exists     bool
	Text       *Pattern
	Properties map[string]*Pattern
	Attributes map[string]*Pattern
}

// ImpliesEntry represents an implied technology with a confidence level
type ImpliesEntry struct {
	Name       string
	Confidence int
}

// Detection is produced when a pattern matches during analysis
type Detection struct {
	Technology *Technology
	Pattern    MatchedPattern
	Version    string
}

// MatchedPattern records which pattern matched on what data
type MatchedPattern struct {
	Type       string
	Value      string
	Match      string
	Regex      string
	Confidence int
	Version    string
}

// Category from categories.json
type Category struct {
	ID       int    `json:"-"`
	Name     string `json:"name"`
	Slug     string `json:"-"`
	Priority int    `json:"priority"`
	Groups   []int  `json:"groups"`
}

// RequiresGroup groups technologies that require a specific technology or category
type RequiresGroup struct {
	Name         string
	CategoryID   int
	Technologies []*Technology
}

// PageData holds everything extracted from a page load
type PageData struct {
	URL        string
	HTML       string
	Text       string
	CSS        string
	Cookies    map[string][]string
	Headers    map[string][]string
	Meta       map[string][]string
	ScriptSrc  []string
	Scripts    string
	CertIssuer string
	DNS        map[string][]string
	Robots     string
	Magento    string
	JSResults    []JSResult
	DOMResults   []DOMResult
	XHRHostnames []string
}

// JSResult holds a detected JS global property
type JSResult struct {
	Name  string      `json:"name"`
	Chain string      `json:"chain"`
	Value interface{} `json:"value"`
}

// DOMResult holds a DOM detection result
type DOMResult struct {
	Name      string `json:"name"`
	Selector  string `json:"selector"`
	Exists    string `json:"exists,omitempty"`
	Text      string `json:"text,omitempty"`
	Property  string `json:"property,omitempty"`
	Attribute string `json:"attribute,omitempty"`
	Value     string `json:"value,omitempty"`
}

// ResolvedTechnology is the final output after resolution
type ResolvedTechnology struct {
	Name       string   `json:"name"`
	Version    *string  `json:"version"`
	Confidence int      `json:"confidence"`
	CPE        *string  `json:"cpe"`
	Categories []string `json:"categories"`
}
