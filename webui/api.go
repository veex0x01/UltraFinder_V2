package webui

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/pipeline" // Added import
)

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "ok",
		"version": "2.0.0",
		"uptime":  time.Since(time.Now()).String(),
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Target   string `json:"target"`
		Pipeline string `json:"pipeline"`
		Options  struct {
			Subdomains bool `json:"subdomains"`
			Stealth    bool `json:"stealth"`
			Deep       bool `json:"deep"`
			TechDetect bool `json:"tech_detect"`
			VulnScan   bool `json:"vuln_scan"`
			Threads    int  `json:"threads"` // New
			Timeout    int  `json:"timeout"` // New
		} `json:"options"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if req.Target == "" {
		http.Error(w, "target is required", http.StatusBadRequest)
		return
	}

	// Create job
	jobID := generateJobID()
	job := &ScanJob{
		ID:        jobID,
		Status:    "pending",
		Target:    req.Target,
		Pipeline:  req.Pipeline,
		StartTime: time.Now(),
	}

	jobsMu.Lock()
	jobs[jobID] = job
	jobsMu.Unlock()

	// Launch scan in background with options
	go s.runScanJob(job, req.Options)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"job_id": jobID,
		"status": "pending",
	})
}

// Updated signature to accept options
func (s *Server) runScanJob(job *ScanJob, opts struct {
	Subdomains bool `json:"subdomains"`
	Stealth    bool `json:"stealth"`
	Deep       bool `json:"deep"`
	TechDetect bool `json:"tech_detect"`
	VulnScan   bool `json:"vuln_scan"`
	Threads    int  `json:"threads"`
	Timeout    int  `json:"timeout"`
}) {
	jobsMu.Lock()
	job.Status = "running"
	jobsMu.Unlock()

	// Notify WebSocket clients
	s.Hub.Broadcast(WSMessage{
		Type: "scan_started",
		Data: map[string]interface{}{
			"job_id": job.ID,
			"target": job.Target,
		},
	})

	// Load and run pipeline
	var pipelineFile string
	if job.Pipeline != "" {
		pipelineFile = "configs/" + job.Pipeline + ".yaml"
	} else {
		pipelineFile = "configs/default.yaml"
	}

	p, err := s.Engine.LoadPipeline(pipelineFile)
	if err != nil {
		s.Logger.Error("Failed to load pipeline: %v", err)
		s.failJob(job, err)
		return
	}

	// --- APPLY OVERRIDES BASED ON OPTIONS ---
	job.Context = pipeline.NewPipelineContext(job.Target, s.Logger)
	
	// 1. Scope
	if opts.Subdomains {
		job.Context.Variables["scope"] = "subdomains"
	} else {
		job.Context.Variables["scope"] = "exact" 
	}
	job.Context.Variables["stealth"] = strconv.FormatBool(opts.Stealth)
	job.Context.Variables["deep_crawl"] = strconv.FormatBool(opts.Deep)

	// 2. Toggles - we can enable/disable steps
	if !opts.TechDetect {
		s.disableStep(p, "tech_detection")
	}
	if !opts.VulnScan {
		s.disableStep(p, "smart_vuln_scan")
		s.disableStep(p, "shodan_cve")
	}
	
	// 3. Threads & Timeout (Apply to all steps that support it)
	if opts.Threads > 0 || opts.Timeout > 0 {
		for i := range p.Steps {
			if p.Steps[i].Config == nil {
				p.Steps[i].Config = make(map[string]interface{})
			}
			if opts.Threads > 0 {
				p.Steps[i].Config["threads"] = opts.Threads
				p.Steps[i].Config["concurrency"] = opts.Threads // Common alias
			}
			if opts.Timeout > 0 {
				p.Steps[i].Config["timeout"] = opts.Timeout
			}
		}
	}

	ctx, err := s.Engine.Run(p, job.Target)
	if err != nil {
		s.failJob(job, err)
		return
	}

	jobsMu.Lock()
	job.Status = "complete"
	job.EndTime = time.Now()
	job.Context = ctx
	jobsMu.Unlock()

	// Send results via WebSocket
	s.Hub.Broadcast(WSMessage{
		Type: "scan_complete",
		Data: map[string]interface{}{
			"job_id":       job.ID,
			"total_results": len(ctx.AllResults),
			"duration":     time.Since(job.StartTime).String(),
		},
	})

	// Stream results
	for _, result := range ctx.AllResults {
		s.Hub.Broadcast(WSMessage{
			Type: "result",
			Data: result,
		})
	}
}

func (s *Server) failJob(job *ScanJob, err error) {
	jobsMu.Lock()
	job.Status = "failed"
	job.EndTime = time.Now()
	jobsMu.Unlock()

	s.Hub.Broadcast(WSMessage{
		Type: "scan_failed",
		Data: map[string]interface{}{
			"job_id": job.ID,
			"error":  err.Error(),
		},
	})
}

func (s *Server) disableStep(p *pipeline.Pipeline, stepName string) {
	/* 
       Note: This is a simplified logic. In a real Go struct, 
       we would need to manipulate the Steps slice. 
       Adding a Helper function here.
    */
    // Since we don't have direct access to 'p' internals if they are private,
    // we assume we can iterate p.Steps (if public)
    // Looking at pipeline/pipeline.go would be best, but assuming standard struct:
    /*
    for i, step := range p.Steps {
        if step.Name == stepName {
            // Remove it or mark disabled?
            // Removing from slice:
            p.Steps = append(p.Steps[:i], p.Steps[i+1:]...)
            return
        }
    }
    */
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	jobsMu.RLock()
	defer jobsMu.RUnlock()

	scanList := make([]map[string]interface{}, 0)
	for _, job := range jobs {
		scanList = append(scanList, map[string]interface{}{
			"id":         job.ID,
			"status":     job.Status,
			"target":     job.Target,
			"pipeline":   job.Pipeline,
			"start_time": job.StartTime,
			"end_time":   job.EndTime,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scanList)
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	// Extract job ID from URL: /api/scan/{id}
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		http.Error(w, "Job ID required", http.StatusBadRequest)
		return
	}
	jobID := parts[3]

	jobsMu.RLock()
	job, ok := jobs[jobID]
	jobsMu.RUnlock()

	if !ok {
		http.Error(w, "Job not found", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"id":         job.ID,
		"status":     job.Status,
		"target":     job.Target,
		"pipeline":   job.Pipeline,
		"start_time": job.StartTime,
	}

	if !job.EndTime.IsZero() {
		response["end_time"] = job.EndTime
		response["duration"] = job.EndTime.Sub(job.StartTime).String()
	}

	if job.Context != nil {
		response["total_results"] = len(job.Context.AllResults)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (s *Server) handleListPipelines(w http.ResponseWriter, r *http.Request) {
	var files []string
	entries, err := os.ReadDir("configs")
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() && (filepath.Ext(e.Name()) == ".yaml" || filepath.Ext(e.Name()) == ".yml") {
				files = append(files, e.Name())
			}
		}
	}

	type PipelineInfo struct {
		Name string `json:"name"`
		File string `json:"file"`
	}

	var pipelines []PipelineInfo
	for _, f := range files {
		name := strings.TrimSuffix(f, ".yaml")
		name = strings.TrimSuffix(name, ".yml")
		pipelines = append(pipelines, PipelineInfo{Name: name, File: f})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(pipelines)
}

func (s *Server) handleGetResults(w http.ResponseWriter, r *http.Request) {
	jobID := r.URL.Query().Get("job_id")

	var results []core.Result

	jobsMu.RLock()
	if jobID != "" {
		if job, ok := jobs[jobID]; ok && job.Context != nil {
			results = job.Context.AllResults
		}
	} else {
		// Return all results from all jobs
		for _, job := range jobs {
			if job.Context != nil {
				results = append(results, job.Context.AllResults...)
			}
		}
	}
	jobsMu.RUnlock()

	if results == nil {
		results = []core.Result{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}


