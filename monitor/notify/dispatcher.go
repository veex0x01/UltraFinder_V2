package notify

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/reporting"
)

// Alert represents a notification to be sent
type Alert struct {
	Title     string
	Message   string
	Severity  string // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Target    string
	Results   []core.Result
	Timestamp time.Time
}

// Notifier is the interface for all notification channels
type Notifier interface {
	Name() string
	Send(alert Alert) error
}

// Dispatcher sends alerts to all configured notification channels
type Dispatcher struct {
	channels []Notifier
	logger   *reporting.Logger
	mu       sync.Mutex
}

// NewDispatcher creates a new Dispatcher
func NewDispatcher(logger *reporting.Logger) *Dispatcher {
	return &Dispatcher{
		channels: make([]Notifier, 0),
		logger:   logger,
	}
}

// AddChannel registers a notification channel
func (d *Dispatcher) AddChannel(channel Notifier) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.channels = append(d.channels, channel)
	d.logger.Info("Registered notification channel: %s", channel.Name())
}

// Dispatch sends an alert to all channels
func (d *Dispatcher) Dispatch(alert Alert) {
	d.mu.Lock()
	channels := append([]Notifier{}, d.channels...)
	d.mu.Unlock()

	if alert.Timestamp.IsZero() {
		alert.Timestamp = time.Now()
	}

	for _, ch := range channels {
		go func(c Notifier) {
			if err := c.Send(alert); err != nil {
				d.logger.Error("Failed to send to %s: %v", c.Name(), err)
			}
		}(ch)
	}
}

// DispatchResults creates an alert from scan results and dispatches it
func (d *Dispatcher) DispatchResults(target string, results []core.Result) {
	if len(results) == 0 {
		return
	}

	// Determine highest severity
	maxSeverity := "INFO"
	severityOrder := map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	for _, r := range results {
		if order, ok := severityOrder[r.Severity]; ok {
			if order > severityOrder[maxSeverity] {
				maxSeverity = r.Severity
			}
		}
	}

	alert := Alert{
		Title:    fmt.Sprintf("🔍 UltraFinder: %d findings for %s", len(results), target),
		Message:  formatResultsSummary(results),
		Severity: maxSeverity,
		Target:   target,
		Results:  results,
	}

	d.Dispatch(alert)
}

// formatResultsSummary creates a text summary of results
func formatResultsSummary(results []core.Result) string {
	var sb strings.Builder
	byType := make(map[string]int)
	bySeverity := make(map[string]int)

	for _, r := range results {
		byType[r.Type]++
		if r.Severity != "" {
			bySeverity[r.Severity]++
		}
	}

	sb.WriteString("📊 Summary:\n")
	for sev, count := range bySeverity {
		sb.WriteString(fmt.Sprintf("  %s: %d\n", sev, count))
	}

	sb.WriteString("\n📋 By Type:\n")
	for typ, count := range byType {
		sb.WriteString(fmt.Sprintf("  %s: %d\n", typ, count))
	}

	// Show top 5 critical/high findings
	sb.WriteString("\n🔴 Top Findings:\n")
	shown := 0
	for _, r := range results {
		if (r.Severity == "CRITICAL" || r.Severity == "HIGH") && shown < 5 {
			sb.WriteString(fmt.Sprintf("  [%s] %s %s\n", r.Severity, r.Type, r.URL))
			shown++
		}
	}

	return sb.String()
}
