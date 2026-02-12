package authscan

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/veex0x01/ultrafinder/core"
	"github.com/veex0x01/ultrafinder/reporting"
)

// CapturedRequest represents an intercepted HTTP request/response
type CapturedRequest struct {
	Method     string
	URL        string
	Headers    http.Header
	Body       []byte
	StatusCode int
}

// InterceptProxy is an HTTP proxy that captures and optionally tests requests
type InterceptProxy struct {
	ListenAddr  string
	TargetScope string // Only intercept requests matching this domain
	Sessions    *SessionManager
	AutoTest    bool // Auto-test captured requests for auth bugs
	Logger      *reporting.Logger
	Output      *core.Output
	Captured    []CapturedRequest
	Results     []core.Result
	mu          sync.Mutex
}

// NewInterceptProxy creates a new proxy
func NewInterceptProxy(listenAddr, scope string, sessions *SessionManager, logger *reporting.Logger) *InterceptProxy {
	return &InterceptProxy{
		ListenAddr:  listenAddr,
		TargetScope: scope,
		Sessions:    sessions,
		Logger:      logger,
		Captured:    make([]CapturedRequest, 0),
		Results:     make([]core.Result, 0),
	}
}

// Start launches the HTTP proxy
func (p *InterceptProxy) Start() error {
	p.Logger.Info("Starting intercepting proxy on %s (scope: %s)", p.ListenAddr, p.TargetScope)

	server := &http.Server{
		Addr:    p.ListenAddr,
		Handler: http.HandlerFunc(p.handleProxy),
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	return server.ListenAndServe()
}

func (p *InterceptProxy) handleProxy(w http.ResponseWriter, req *http.Request) {
	// Check scope
	if p.TargetScope != "" && !strings.Contains(req.Host, p.TargetScope) {
		// Out of scope — pass through
		p.forwardRequest(w, req)
		return
	}

	// Read request body
	body, _ := io.ReadAll(req.Body)

	// Forward to target
	targetURL := req.URL.String()
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "https://" + req.Host + req.URL.RequestURI()
	}

	proxyReq, err := http.NewRequest(req.Method, targetURL, strings.NewReader(string(body)))
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Copy headers
	for k, v := range req.Header {
		proxyReq.Header[k] = v
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	// Store captured request
	captured := CapturedRequest{
		Method:     req.Method,
		URL:        targetURL,
		Headers:    req.Header.Clone(),
		Body:       body,
		StatusCode: resp.StatusCode,
	}

	p.mu.Lock()
	p.Captured = append(p.Captured, captured)
	p.mu.Unlock()

	p.Logger.Debug("[PROXY] %s %s → %d", req.Method, targetURL, resp.StatusCode)

	// Auto-test if enabled
	if p.AutoTest && p.Sessions != nil {
		go p.autoTest(captured)
	}

	// Send response back to client
	for k, v := range resp.Header {
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

func (p *InterceptProxy) forwardRequest(w http.ResponseWriter, req *http.Request) {
	targetURL := req.URL.String()
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + req.Host + req.URL.RequestURI()
	}

	proxyReq, err := http.NewRequest(req.Method, targetURL, req.Body)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	for k, v := range req.Header {
		proxyReq.Header[k] = v
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "Upstream error", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	for k, v := range resp.Header {
		for _, val := range v {
			w.Header().Add(k, val)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(body)
}

func (p *InterceptProxy) autoTest(captured CapturedRequest) {
	// Test with different sessions
	sessions := []string{"low", "high"}
	for _, sessionName := range sessions {
		session := p.Sessions.GetSession(sessionName)
		if session == nil {
			continue
		}

		resp, err := p.Sessions.SendRequest(captured.Method, captured.URL, sessionName, nil)
		if err != nil {
			continue
		}

		if resp.StatusCode == captured.StatusCode {
			p.mu.Lock()
			p.Results = append(p.Results, core.Result{
				Type:     "idor",
				URL:      captured.URL,
				Source:   "proxy-auto-test",
				Tool:     "proxy",
				Severity: "MEDIUM",
				Evidence: fmt.Sprintf("Session '%s' got same status %d", sessionName, resp.StatusCode),
			})
			p.mu.Unlock()
		}
	}
}

// GetCaptured returns all captured requests
func (p *InterceptProxy) GetCaptured() []CapturedRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]CapturedRequest{}, p.Captured...)
}

// GetResults returns auth test results
func (p *InterceptProxy) GetResults() []core.Result {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]core.Result{}, p.Results...)
}

// GetLocalIP returns the machine's local IP for display
func GetLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String()
			}
		}
	}
	return "127.0.0.1"
}
