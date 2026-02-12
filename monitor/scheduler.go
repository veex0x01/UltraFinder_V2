package monitor

import (
	"fmt"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/monitor/notify"
	"github.com/veex0x01/ultrafinder/reporting"
)

// WatchTarget is a URL/domain being monitored
type WatchTarget struct {
	URL             string        `yaml:"url"`
	Interval        time.Duration `yaml:"interval"`
	Screenshot      bool          `yaml:"screenshot"`
	ContentDiff     bool          `yaml:"content_diff"`
	ChangeThreshold float64       `yaml:"change_threshold"` // 0.0-1.0 for screenshot
}

// Scheduler runs monitoring jobs on intervals
type Scheduler struct {
	Targets    []WatchTarget
	Screenshot *ScreenshotEngine
	Diff       *DiffMonitor
	Notifier   *notify.Dispatcher
	Logger     *reporting.Logger
	running    bool
	stopCh     chan struct{}
}

// NewScheduler creates a new monitoring scheduler
func NewScheduler(logger *reporting.Logger, dispatcher *notify.Dispatcher) *Scheduler {
	return &Scheduler{
		Targets:  make([]WatchTarget, 0),
		Notifier: dispatcher,
		Logger:   logger,
		stopCh:   make(chan struct{}),
	}
}

// AddTarget adds a watch target
func (s *Scheduler) AddTarget(target WatchTarget) {
	if target.Interval == 0 {
		target.Interval = 1 * time.Hour
	}
	if target.ChangeThreshold == 0 {
		target.ChangeThreshold = 0.95
	}
	s.Targets = append(s.Targets, target)
}

// Start begins the monitoring loop
func (s *Scheduler) Start() {
	s.running = true
	s.Logger.Info("Starting monitor scheduler with %d targets", len(s.Targets))

	for _, target := range s.Targets {
		go s.watchLoop(target)
	}
}

// Stop halts all monitoring
func (s *Scheduler) Stop() {
	s.running = false
	close(s.stopCh)
	s.Logger.Info("Monitor scheduler stopped")
}

func (s *Scheduler) watchLoop(target WatchTarget) {
	ticker := time.NewTicker(target.Interval)
	defer ticker.Stop()

	// Run immediately on start
	s.checkTarget(target)

	for {
		select {
		case <-ticker.C:
			s.checkTarget(target)
		case <-s.stopCh:
			return
		}
	}
}

func (s *Scheduler) checkTarget(target WatchTarget) {
	s.Logger.Debug("Checking target: %s", target.URL)
	var results []core.Result

	// Screenshot comparison
	if target.Screenshot && s.Screenshot != nil {
		result, err := s.Screenshot.DetectChanges(target.URL, target.ChangeThreshold)
		if err != nil {
			s.Logger.Error("Screenshot check failed for %s: %v", target.URL, err)
		}
		if result != nil {
			results = append(results, *result)
		}
	}

	// Content diff
	if target.ContentDiff && s.Diff != nil {
		dr, err := s.Diff.CheckForChanges(target.URL)
		if err != nil {
			s.Logger.Error("Diff check failed for %s: %v", target.URL, err)
		}
		if dr != nil && dr.Changed {
			result := s.Diff.ToResult(dr)
			if result != nil {
				results = append(results, *result)
			}
		}
	}

	// Dispatch notifications for changes
	if len(results) > 0 {
		s.Logger.Warn("%d changes detected for %s", len(results), target.URL)
		s.Notifier.Dispatch(notify.Alert{
			Title:   fmt.Sprintf("🔔 UltraFinder: Changes detected on %s", target.URL),
			Message: fmt.Sprintf("%d changes detected", len(results)),
			Target:  target.URL,
			Results: results,
		})
	}
}

// RunOnce performs a single check of all targets (for CLI use)
func (s *Scheduler) RunOnce() []core.Result {
	var allResults []core.Result
	for _, target := range s.Targets {
		s.Logger.Info("Checking: %s", target.URL)

		if target.Screenshot && s.Screenshot != nil {
			result, err := s.Screenshot.DetectChanges(target.URL, target.ChangeThreshold)
			if err != nil {
				s.Logger.Error("Screenshot failed: %v", err)
			}
			if result != nil {
				allResults = append(allResults, *result)
			}
		}

		if target.ContentDiff && s.Diff != nil {
			dr, err := s.Diff.CheckForChanges(target.URL)
			if err != nil {
				s.Logger.Error("Diff failed: %v", err)
			}
			if dr != nil && dr.Changed {
				result := s.Diff.ToResult(dr)
				if result != nil {
					allResults = append(allResults, *result)
				}
			}
		}
	}
	return allResults
}
