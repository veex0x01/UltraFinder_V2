package webui

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"sync"
	"time"

	"github.com/veex0x01/ultrafinder/pipeline"
	"github.com/veex0x01/ultrafinder/reporting"
)

//go:embed frontend/*
var frontendFS embed.FS

// Server is the web UI HTTP server
type Server struct {
	ListenAddr string
	Engine     *pipeline.Engine
	Logger     *reporting.Logger
	Hub        *WSHub
	auth       *BasicAuth
	mux        *http.ServeMux
}

// BasicAuth holds credentials for basic auth
type BasicAuth struct {
	Username string
	Password string
}

// ScanJob represents a running or completed scan job
type ScanJob struct {
	ID        string               `json:"id"`
	Status    string               `json:"status"` // pending, running, complete, failed
	Target    string               `json:"target"`
	Pipeline  string               `json:"pipeline"`
	StartTime time.Time            `json:"start_time"`
	EndTime   time.Time            `json:"end_time,omitempty"`
	Context   *pipeline.PipelineContext `json:"-"`
}

var (
	jobsMu sync.RWMutex
	jobs   = make(map[string]*ScanJob)
)

// NewServer creates a new web UI server
func NewServer(addr string, engine *pipeline.Engine, logger *reporting.Logger, user, pass string) *Server {
	s := &Server{
		ListenAddr: addr,
		Engine:     engine,
		Logger:     logger,
		Hub:        NewWSHub(),
		mux:        http.NewServeMux(),
	}

	if user != "" && pass != "" {
		s.auth = &BasicAuth{Username: user, Password: pass}
	}

	s.setupRoutes()
	return s
}

func (s *Server) setupRoutes() {
	// API routes
	s.mux.HandleFunc("/api/health", s.withAuth(s.handleHealth))
	s.mux.HandleFunc("/api/scan", s.withAuth(s.handleScan))
	s.mux.HandleFunc("/api/scans", s.withAuth(s.handleListScans))
	s.mux.HandleFunc("/api/scan/", s.withAuth(s.handleGetScan))
	s.mux.HandleFunc("/api/pipelines", s.withAuth(s.handleListPipelines))
	s.mux.HandleFunc("/api/results", s.withAuth(s.handleGetResults))

	// WebSocket
	s.mux.HandleFunc("/ws", s.handleWebSocket)

	// Static frontend
	frontend, err := fs.Sub(frontendFS, "frontend")
	if err != nil {
		s.Logger.Error("Failed to load frontend: %v", err)
		return
	}
	s.mux.Handle("/", http.FileServer(http.FS(frontend)))
}

// Start launches the web server
func (s *Server) Start() error {
	// Start WebSocket hub
	go s.Hub.Run()

	// Register Logger Callback to stream logs to WebSocket
	s.Logger.SetCallback(func(level reporting.LogLevel, msg string) {
		s.Hub.Broadcast(WSMessage{
			Type: "log",
			Data: map[string]string{
				"level":     reporting.LogLevelNames[level],
				"message":   msg,
				"timestamp": time.Now().Format(time.RFC3339),
			},
		})
	})

	s.Logger.Success("Web UI running on http://%s", s.ListenAddr)
	if s.auth != nil {
		s.Logger.Info("Basic auth enabled (user: %s)", s.auth.Username)
	}

	server := &http.Server{
		Addr:    s.ListenAddr,
		Handler: s.mux,
	}

	return server.ListenAndServe()
}

func (s *Server) withAuth(next http.HandlerFunc) http.HandlerFunc {
	if s.auth == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != s.auth.Username || pass != s.auth.Password {
			w.Header().Set("WWW-Authenticate", `Basic realm="UltraFinder"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func generateJobID() string {
	return fmt.Sprintf("scan_%d", time.Now().UnixNano())
}
