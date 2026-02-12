package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Colors for output
var (
	ColorRed     = color.New(color.FgRed, color.Bold)
	ColorGreen   = color.New(color.FgGreen, color.Bold)
	ColorYellow  = color.New(color.FgYellow, color.Bold)
	ColorBlue    = color.New(color.FgBlue, color.Bold)
	ColorMagenta = color.New(color.FgMagenta, color.Bold)
	ColorCyan    = color.New(color.FgCyan, color.Bold)
	ColorWhite   = color.New(color.FgWhite, color.Bold)
)

// Result represents a finding
type Result struct {
	Type       string `json:"type"`
	URL        string `json:"url"`
	Source     string `json:"source,omitempty"`
	Parameter  string `json:"parameter,omitempty"`
	Value      string `json:"value,omitempty"`
	Confidence string `json:"confidence,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	// v2.0 fields
	Severity  string `json:"severity,omitempty"`  // CRITICAL, HIGH, MEDIUM, LOW, INFO
	CVEID     string `json:"cve_id,omitempty"`    // CVE-2021-44228
	Tool      string `json:"tool,omitempty"`      // Which tool found this
	Evidence  string `json:"evidence,omitempty"` // Proof/snippet
	Timestamp string `json:"timestamp,omitempty"` // When found
}

// NewResult creates a Result with timestamp auto-populated
func NewResult(resultType, url string) Result {
	return Result{
		Type:      resultType,
		URL:       url,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}
}

// Output handles writing results
type Output struct {
	file       *os.File
	writer     *bufio.Writer
	jsonOutput bool
	quiet      bool
	mu         sync.Mutex
	Callback   func(Result) // Optional callback for captures
}

// NewOutput creates a new Output handler
func NewOutput(filename string, jsonOutput, quiet bool) (*Output, error) {
	o := &Output{
		jsonOutput: jsonOutput,
		quiet:      quiet,
	}

	if filename != "" {
		file, err := os.Create(filename)
		if err != nil {
			return nil, err
		}
		o.file = file
		o.writer = bufio.NewWriter(file)
	}

	return o, nil
}

// Close closes the output file
func (o *Output) Close() {
	if o.writer != nil {
		o.writer.Flush()
	}
	if o.file != nil {
		o.file.Close()
	}
}

// WriteResult writes a result to output
func (o *Output) WriteResult(result Result) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Trigger callback if set
	if o.Callback != nil {
		o.Callback(result)
	}

	var output string
	if o.jsonOutput {
		data, _ := json.Marshal(result)
		output = string(data)
	} else {
		output = o.formatResult(result)
	}

	if !o.quiet {
		o.printColored(result)
	}

	if o.writer != nil {
		o.writer.WriteString(output + "\n")
	}
}

// formatResult formats a result as plain text
func (o *Output) formatResult(result Result) string {
	base := fmt.Sprintf("[%s] %s", result.Type, result.URL)
	if result.Parameter != "" {
		base += fmt.Sprintf(" | %s=%s", result.Parameter, result.Value)
	}
	if result.Confidence != "" {
		base += fmt.Sprintf(" (%s)", result.Confidence)
	}
	if result.Severity != "" {
		base += fmt.Sprintf(" [%s]", result.Severity)
	}
	if result.CVEID != "" {
		base += fmt.Sprintf(" %s", result.CVEID)
	}
	if result.Tool != "" {
		base += fmt.Sprintf(" (via %s)", result.Tool)
	}
	return base
}

// printColored prints a colored result to console
func (o *Output) printColored(result Result) {
	var typeColor *color.Color
	switch result.Type {
	case "url", "href":
		typeColor = ColorGreen
	case "js", "javascript", "linkfinder":
		typeColor = ColorYellow
	case "form", "upload-form":
		typeColor = ColorBlue
	case "sensitive-param", "hidden-field":
		typeColor = ColorRed
	case "sensitive-path":
		typeColor = ColorMagenta
	case "subdomain":
		typeColor = ColorCyan
	case "aws-s3":
		typeColor = ColorRed
	case "wayback", "commoncrawl", "otx":
		typeColor = ColorMagenta
	// v2.0 types
	case "sqli", "xss", "lfi", "rce", "ssrf", "idor", "privesc", "auth-bypass":
		typeColor = ColorRed
	case "cve":
		typeColor = ColorRed
	case "technology":
		typeColor = ColorCyan
	case "open-port":
		typeColor = ColorBlue
	case "source-map", "secret":
		typeColor = ColorRed
	case "screenshot-diff", "content-diff":
		typeColor = ColorYellow
	default:
		typeColor = ColorWhite
	}

	typeColor.Printf("[%s] ", result.Type)
	fmt.Printf("%s", result.URL)
	
	if result.Parameter != "" {
		ColorYellow.Printf(" | %s", result.Parameter)
		fmt.Printf("=%s", result.Value)
	}
	if result.Confidence != "" {
		ColorCyan.Printf(" (%s)", result.Confidence)
	}
	if result.Severity != "" {
		sevColor := ColorWhite
		switch result.Severity {
		case "CRITICAL":
			sevColor = ColorRed
		case "HIGH":
			sevColor = color.New(color.FgRed)
		case "MEDIUM":
			sevColor = ColorYellow
		case "LOW":
			sevColor = ColorBlue
		case "INFO":
			sevColor = ColorCyan
		}
		sevColor.Printf(" [%s]", result.Severity)
	}
	if result.CVEID != "" {
		ColorRed.Printf(" %s", result.CVEID)
	}
	if result.Tool != "" {
		ColorMagenta.Printf(" (via %s)", result.Tool)
	}
	if result.StatusCode > 0 {
		fmt.Printf(" [%d]", result.StatusCode)
	}
	fmt.Println()
}

// Info prints an info message
func Info(format string, args ...interface{}) {
	ColorBlue.Printf("[*] ")
	fmt.Printf(format+"\n", args...)
}

// Success prints a success message
func Success(format string, args ...interface{}) {
	ColorGreen.Printf("[+] ")
	fmt.Printf(format+"\n", args...)
}

// Warning prints a warning message
func Warning(format string, args ...interface{}) {
	ColorYellow.Printf("[!] ")
	fmt.Printf(format+"\n", args...)
}

// Error prints an error message
func Error(format string, args ...interface{}) {
	ColorRed.Printf("[-] ")
	fmt.Printf(format+"\n", args...)
}

// PrintBanner prints the tool banner
func PrintBanner() {
	banner := `
   __  ______             _______           __         
  / / / / / /__________ _/ ____(_)___  ____/ /__  _____
 / / / / / __/ ___/ __ '/ /_  / / __ \/ __  / _ \/ ___/
/ /_/ / / /_/ /  / /_/ / __/ / / / / / /_/ /  __/ /    
\____/_/\__/_/   \__,_/_/   /_/_/ /_/\__,_/\___/_/     
`
	ColorCyan.Println(banner)
	ColorYellow.Println("        Advanced Web Reconnaissance Tool")
	ColorMagenta.Println("               by veex0x01")
	fmt.Println()
	ColorWhite.Println("---------------------------------------------------")
	fmt.Println()
}

