package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"techfinder/internal/browser"
	"techfinder/internal/probe"
	"techfinder/internal/wappalyzer"
)

const defaultUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36"

func main() {
	args := os.Args[1:]
	opts := map[string]interface{}{}
	var targetURL string

	aliases := map[string]string{
		"a": "userAgent",
		"d": "debug",
		"h": "help",
		"H": "header",
		"w": "maxWait",
		"p": "probe",
		"n": "noScripts",
		"N": "noRedirect",
	}

	for len(args) > 0 {
		arg := args[0]
		args = args[1:]

		if strings.HasPrefix(arg, "-") {
			// Strip leading dashes
			key := strings.TrimLeft(arg, "-")
			var value interface{}

			// Check for =value
			if idx := strings.Index(key, "="); idx >= 0 {
				value = key[idx+1:]
				key = key[:idx]
			} else if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
				value = args[0]
				args = args[1:]
			} else {
				value = true
			}

			// Resolve alias
			if alias, ok := aliases[key]; ok {
				key = alias
			} else {
				// Convert kebab-case to camelCase
				parts := strings.Split(key, "-")
				for i := 1; i < len(parts); i++ {
					if len(parts[i]) > 0 {
						parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
					}
				}
				key = strings.Join(parts, "")
			}

			// Handle multiple values (e.g. multiple -H)
			if existing, ok := opts[key]; ok {
				if arr, ok := existing.([]string); ok {
					opts[key] = append(arr, fmt.Sprint(value))
				} else {
					opts[key] = []string{fmt.Sprint(existing), fmt.Sprint(value)}
				}
			} else {
				opts[key] = value
			}
		} else {
			targetURL = arg
		}
	}

	if targetURL == "" || opts["help"] == true {
		fmt.Print(`
  TechFinder - Technology Detection Tool

  Usage:
    techfinder <url> [options]

  Examples:
    techfinder https://example.com
    techfinder https://example.com -p
    techfinder https://example.com -H "Cookie: token=abc"

  Options:
    -d, --debug            Debug output
    -h, --help             Show this help
    -H, --header           Extra header to send with requests
    -w, --max-wait=ms      Max wait for page resources (default: 30000)
    -p, --probe            Deep scan (DNS records, robots.txt, etc.)
    -a, --user-agent=...   Set user agent string
    -n, --no-scripts       Disable JavaScript on pages
    -N, --no-redirect      Disable cross-domain redirects
    --proxy=...            Proxy URL, e.g. 'http://user:pass@proxy:8080'

`)
		if opts["help"] == true {
			os.Exit(0)
		}
		os.Exit(1)
	}

	// Parse URL
	parsed, err := url.Parse(targetURL)
	if err != nil || parsed.Host == "" {
		// Try adding https://
		if !strings.Contains(targetURL, "://") {
			targetURL = "https://" + targetURL
			parsed, err = url.Parse(targetURL)
		}
		if err != nil || parsed.Host == "" {
			fmt.Fprintf(os.Stderr, "Invalid URL: %s\n", targetURL)
			os.Exit(1)
		}
	}

	// Strip fragment
	parsed.Fragment = ""
	targetURL = parsed.String()

	// Build options
	maxWait := 30000
	if v, ok := opts["maxWait"]; ok {
		if n, err := strconv.Atoi(fmt.Sprint(v)); err == nil {
			maxWait = n
		}
	}

	userAgent := defaultUA
	if v, ok := opts["userAgent"]; ok {
		userAgent = fmt.Sprint(v)
	}

	proxyURL := ""
	if v, ok := opts["proxy"]; ok {
		proxyURL = fmt.Sprint(v)
	}

	headers := make(map[string]string)
	if v, ok := opts["header"]; ok {
		var headerList []string
		switch h := v.(type) {
		case string:
			headerList = []string{h}
		case []string:
			headerList = h
		}
		for _, header := range headerList {
			parts := strings.SplitN(header, ":", 2)
			if len(parts) == 2 {
				headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	browserOpts := browser.Options{
		MaxWait:    maxWait,
		UserAgent:  userAgent,
		Proxy:      proxyURL,
		NoScripts:  opts["noScripts"] == true,
		NoRedirect: opts["noRedirect"] == true,
		Headers:    headers,
		Debug:      opts["debug"] == true,
	}

	// 1. Load fingerprints
	wap, err := wappalyzer.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load fingerprints: %v\n", err)
		os.Exit(1)
	}

	// 2. Launch browser
	b, err := browser.New(browserOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to launch browser: %v\n", err)
		os.Exit(1)
	}
	defer b.Close()

	// 3. Navigate and extract data
	pageData, err := browser.Navigate(b, targetURL, browserOpts, wap.Technologies)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// Debug output
	if opts["debug"] == true {
		fmt.Fprintf(os.Stderr, "\n=== PAGE DATA DEBUG ===\n")
		fmt.Fprintf(os.Stderr, "URL: %s\n", pageData.URL)
		fmt.Fprintf(os.Stderr, "HTML length: %d\n", len(pageData.HTML))
		fmt.Fprintf(os.Stderr, "Scripts: %s\n", pageData.Scripts)
		fmt.Fprintf(os.Stderr, "ScriptSrc count: %d\n", len(pageData.ScriptSrc))
		fmt.Fprintf(os.Stderr, "Headers count: %d\n", len(pageData.Headers))
		fmt.Fprintf(os.Stderr, "Cookies count: %d\n", len(pageData.Cookies))
		fmt.Fprintf(os.Stderr, "Meta count: %d\n", len(pageData.Meta))
		fmt.Fprintf(os.Stderr, "JS Results: %d\n", len(pageData.JSResults))
		fmt.Fprintf(os.Stderr, "DOM Results: %d\n", len(pageData.DOMResults))
		fmt.Fprintf(os.Stderr, "XHR Hostnames: %d\n", len(pageData.XHRHostnames))
		fmt.Fprintf(os.Stderr, "CertIssuer: %s\n", pageData.CertIssuer)
		fmt.Fprintf(os.Stderr, "======================\n\n")
	}

	// 4. Run analysis
	var allDetections []wappalyzer.Detection

	// Standard analysis
	allDetections = append(allDetections, wap.Analyze(pageData, nil)...)

	// JS globals analysis
	if len(pageData.JSResults) > 0 {
		allDetections = append(allDetections, wap.AnalyzeJS(pageData.JSResults, nil)...)
	}

	// DOM analysis
	if len(pageData.DOMResults) > 0 {
		allDetections = append(allDetections, wap.AnalyzeDOM(pageData.DOMResults, nil)...)
	}

	// XHR analysis
	if len(pageData.XHRHostnames) > 0 {
		allDetections = append(allDetections, wap.AnalyzeXHR(pageData.XHRHostnames, nil)...)
	}

	// 5. Probe (optional)
	if opts["probe"] == true {
		probeTimeout := time.Duration(maxWait) * time.Millisecond
		probeResults := probe.Run(targetURL, parsed.Hostname(), userAgent, probeTimeout)

		probeData := &wappalyzer.PageData{
			Robots:  probeResults.Robots,
			Magento: probeResults.Magento,
			DNS:     probeResults.DNS,
		}
		allDetections = append(allDetections, wap.Analyze(probeData, nil)...)
	}

	// 6. Handle requires chains
	allDetections = wap.ProcessRequires(allDetections, pageData)

	// 7. Resolve
	results := wap.Resolve(allDetections)

	// 8. Output JSON
	output := struct {
		Target       string                         `json:"target"`
		Technologies []wappalyzer.ResolvedTechnology `json:"technologies"`
	}{
		Target:       targetURL,
		Technologies: results,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(output)
}
