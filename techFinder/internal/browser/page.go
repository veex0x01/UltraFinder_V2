package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/security"
	"github.com/chromedp/chromedp"

	"techfinder/internal/wappalyzer"
)

// Navigate loads a URL and extracts all data needed for technology detection
func Navigate(b *Browser, targetURL string, opts Options, techs []*wappalyzer.Technology) (*wappalyzer.PageData, error) {
	timeout := time.Duration(opts.MaxWait) * time.Millisecond
	ctx, cancel := context.WithTimeout(b.Ctx, timeout+30*time.Second)
	defer cancel()

	data := &wappalyzer.PageData{
		URL:     targetURL,
		Cookies: make(map[string][]string),
		Headers: make(map[string][]string),
		Meta:    make(map[string][]string),
	}

	var mu sync.Mutex
	var xhrHostnames []string
	xhrSeen := make(map[string]bool)
	var finalURL string

	// Listen for network events
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch e := ev.(type) {
		case *network.EventResponseReceived:
			if e.Response == nil {
				return
			}

			// Capture headers for main document response
			if e.Type == network.ResourceTypeDocument {
				mu.Lock()
				// Track the final URL after redirects
				if finalURL == "" || e.Response.URL != "" {
					finalURL = e.Response.URL
				}

				// Capture headers from document response
				for k, v := range e.Response.Headers {
					key := strings.ToLower(k)
					data.Headers[key] = append(data.Headers[key], fmt.Sprint(v))
				}

				if e.Response.SecurityDetails != nil {
					data.CertIssuer = e.Response.SecurityDetails.Issuer
				}
				mu.Unlock()
			}

		case *network.EventRequestWillBeSent:
			if e.Type == network.ResourceTypeXHR || e.Type == network.ResourceTypeFetch {
				if u, err := url.Parse(e.Request.URL); err == nil {
					mu.Lock()
					hostname := u.Hostname()
					if !xhrSeen[hostname] {
						xhrSeen[hostname] = true
						xhrHostnames = append(xhrHostnames, hostname)
					}
					mu.Unlock()
				}
			}
		}
	})

	// Enable network monitoring first
	enableActions := []chromedp.Action{
		network.Enable(),
		security.SetIgnoreCertificateErrors(true),
	}

	if len(opts.Headers) > 0 {
		hdrs := make(network.Headers)
		for k, v := range opts.Headers {
			hdrs[k] = v
		}
		enableActions = append(enableActions, network.SetExtraHTTPHeaders(hdrs))
	}

	if opts.UserAgent != "" {
		enableActions = append(enableActions, emulation.SetUserAgentOverride(opts.UserAgent))
	}

	// Run network setup first
	if err := chromedp.Run(ctx, enableActions...); err != nil {
		return nil, fmt.Errorf("network setup failed: %w", err)
	}

	// Small delay to ensure network monitoring is active
	time.Sleep(100 * time.Millisecond)

	// Now navigate
	if err := chromedp.Run(ctx, chromedp.Navigate(targetURL)); err != nil {
		return nil, fmt.Errorf("navigation failed: %w", err)
	}

	// Wait for page load
	if !opts.NoScripts {
		chromedp.Run(ctx, chromedp.Sleep(1*time.Second))
	}

	// Extract HTML
	var html string
	if err := chromedp.Run(ctx, chromedp.OuterHTML("html", &html, chromedp.ByQuery)); err != nil {
		html = ""
	}
	data.HTML = truncateHTML(html, 2000, 3000)

	// Extract text, meta, scripts, scriptSrc, css via single JS evaluation
	var extractResult struct {
		Text      string              `json:"text"`
		Meta      map[string][]string `json:"meta"`
		ScriptSrc []string            `json:"scriptSrc"`
		Scripts   []string            `json:"scripts"`
		CSS       string              `json:"css"`
	}

	extractJS := `
(function() {
	var result = {text: '', meta: {}, scriptSrc: [], scripts: [], css: ''};

	// Text
	try {
		result.text = document.body ? document.body.innerText : '';
	} catch(e) {}

	// Meta tags
	try {
		var metas = document.querySelectorAll('meta');
		for (var i = 0; i < metas.length; i++) {
			var key = metas[i].getAttribute('name') || metas[i].getAttribute('property');
			if (key) {
				key = key.toLowerCase();
				if (!result.meta[key]) result.meta[key] = [];
				result.meta[key].push(metas[i].getAttribute('content') || '');
			}
		}
	} catch(e) {}

	// Script tags
	try {
		var scripts = document.getElementsByTagName('script');
		for (var i = 0; i < scripts.length; i++) {
			if (scripts[i].src && !scripts[i].src.startsWith('data:text/javascript;')) {
				result.scriptSrc.push(scripts[i].src);
			}
			if (scripts[i].textContent) {
				result.scripts.push(scripts[i].textContent);
			}
		}
	} catch(e) {}

	// CSS
	try {
		var css = [];
		if (document.styleSheets.length) {
			for (var i = 0; i < document.styleSheets.length; i++) {
				try {
					var rules = document.styleSheets[i].cssRules;
					for (var j = 0; j < rules.length && css.length < 3000; j++) {
						css.push(rules[j].cssText);
					}
				} catch(e) {}
			}
		}
		result.css = css.join('\n');
	} catch(e) {}

	return result;
})()
`
	if err := chromedp.Run(ctx, chromedp.Evaluate(extractJS, &extractResult)); err == nil {
		data.Text = extractResult.Text
		data.Meta = extractResult.Meta
		data.ScriptSrc = extractResult.ScriptSrc
		data.Scripts = strings.Join(extractResult.Scripts, ",")
		data.CSS = extractResult.CSS
	}

	// Extract cookies
	chromedp.Run(ctx, chromedp.ActionFunc(func(ctx context.Context) error {
		cookies, err := network.GetCookies().Do(ctx)
		if err != nil {
			return nil
		}
		for _, c := range cookies {
			name := strings.ToLower(c.Name)
			data.Cookies[name] = append(data.Cookies[name], c.Value)
		}
		return nil
	}))

	// Extract JS globals
	data.JSResults = evalJS(ctx, techs)

	// Extract DOM
	data.DOMResults = evalDOM(ctx, techs)

	// Set XHR hostnames
	mu.Lock()
	data.XHRHostnames = xhrHostnames
	// Update URL to final URL after redirects
	if finalURL != "" {
		data.URL = finalURL
	}
	mu.Unlock()

	return data, nil
}

func evalJS(ctx context.Context, techs []*wappalyzer.Technology) []wappalyzer.JSResult {
	type jsTechInput struct {
		Name   string   `json:"name"`
		Chains []string `json:"chains"`
	}

	var inputs []jsTechInput
	for _, tech := range techs {
		if len(tech.JS) > 0 {
			chains := make([]string, 0, len(tech.JS))
			for chain := range tech.JS {
				chains = append(chains, chain)
			}
			inputs = append(inputs, jsTechInput{Name: tech.Name, Chains: chains})
		}
	}

	if len(inputs) == 0 {
		return nil
	}

	inputJSON, err := json.Marshal(inputs)
	if err != nil {
		return nil
	}

	jsCode := fmt.Sprintf(`
(function(technologies) {
	var results = [];
	for (var t = 0; t < technologies.length; t++) {
		var tech = technologies[t];
		for (var c = 0; c < tech.chains.length; c++) {
			var chain = tech.chains[c].replace(/\[([^\]]+)\]/g, '.$1');
			var parts = chain.split('.');
			var value = window;
			var found = true;
			for (var p = 0; p < parts.length; p++) {
				if (value && typeof value === 'object' && parts[p] in value) {
					value = value[parts[p]];
				} else {
					found = false;
					break;
				}
			}
			if (found) {
				var v;
				if (typeof value === 'string' || typeof value === 'number') {
					v = value;
				} else {
					v = !!value;
				}
				results.push({name: tech.name, chain: tech.chains[c], value: String(v)});
			}
		}
	}
	return results;
})(%s)
`, string(inputJSON))

	var results []wappalyzer.JSResult
	if err := chromedp.Run(ctx, chromedp.Evaluate(jsCode, &results)); err != nil {
		return nil
	}

	return results
}

func evalDOM(ctx context.Context, techs []*wappalyzer.Technology) []wappalyzer.DOMResult {
	type domTechInput struct {
		Name      string                 `json:"name"`
		Selectors map[string]interface{} `json:"selectors"`
	}

	var inputs []domTechInput
	for _, tech := range techs {
		if len(tech.Dom) > 0 {
			selectors := make(map[string]interface{})
			for selector, rules := range tech.Dom {
				ruleData := make([]map[string]interface{}, 0)
				for _, rule := range rules {
					rd := make(map[string]interface{})
					if rule.Exists {
						rd["exists"] = true
					}
					if rule.Text != nil {
						rd["text"] = true
					}
					if rule.Properties != nil {
						props := make(map[string]bool)
						for p := range rule.Properties {
							props[p] = true
						}
						rd["properties"] = props
					}
					if rule.Attributes != nil {
						attrs := make(map[string]bool)
						for a := range rule.Attributes {
							attrs[a] = true
						}
						rd["attributes"] = attrs
					}
					ruleData = append(ruleData, rd)
				}
				selectors[selector] = ruleData
			}
			inputs = append(inputs, domTechInput{Name: tech.Name, Selectors: selectors})
		}
	}

	if len(inputs) == 0 {
		return nil
	}

	inputJSON, err := json.Marshal(inputs)
	if err != nil {
		return nil
	}

	jsCode := fmt.Sprintf(`
(function(technologies) {
	var results = [];
	for (var t = 0; t < technologies.length; t++) {
		var tech = technologies[t];
		var selectors = Object.keys(tech.selectors);
		for (var s = 0; s < selectors.length; s++) {
			var selector = selectors[s];
			var nodes;
			try {
				nodes = document.querySelectorAll(selector);
			} catch(e) {
				continue;
			}
			if (!nodes.length) continue;

			var rules = tech.selectors[selector];
			for (var r = 0; r < rules.length; r++) {
				var rule = rules[r];
				for (var n = 0; n < nodes.length; n++) {
					var node = nodes[n];

					if (rule.exists) {
						results.push({name: tech.name, selector: selector, exists: ''});
					}

					if (rule.text) {
						var text = node.textContent ? node.textContent.trim() : '';
						if (text) {
							results.push({name: tech.name, selector: selector, text: text});
						}
					}

					if (rule.properties) {
						var propKeys = Object.keys(rule.properties);
						for (var pk = 0; pk < propKeys.length; pk++) {
							var prop = propKeys[pk];
							if (prop in node) {
								var pv = node[prop];
								if (typeof pv !== 'undefined') {
									results.push({
										name: tech.name, selector: selector,
										property: prop,
										value: typeof pv === 'string' || typeof pv === 'number' ? String(pv) : String(!!pv)
									});
								}
							}
						}
					}

					if (rule.attributes) {
						var attrKeys = Object.keys(rule.attributes);
						for (var ak = 0; ak < attrKeys.length; ak++) {
							var attr = attrKeys[ak];
							if (node.hasAttribute(attr)) {
								results.push({
									name: tech.name, selector: selector,
									attribute: attr, value: node.getAttribute(attr) || ''
								});
							}
						}
					}
				}
			}
		}
	}
	return results;
})(%s)
`, string(inputJSON))

	var results []wappalyzer.DOMResult
	if err := chromedp.Run(ctx, chromedp.Evaluate(jsCode, &results)); err != nil {
		return nil
	}

	return results
}

func truncateHTML(html string, maxCols, maxRows int) string {
	if maxCols == 0 || maxRows == 0 || len(html) == 0 {
		return html
	}

	rows := len(html) / maxCols
	if rows <= maxRows {
		return html
	}

	var buf strings.Builder
	for i := 0; i < rows; i++ {
		if i < maxRows/2 || i > rows-maxRows/2 {
			start := i * maxCols
			end := (i + 1) * maxCols
			if end > len(html) {
				end = len(html)
			}
			buf.WriteString(html[start:end])
			buf.WriteByte('\n')
		}
	}
	return buf.String()
}
