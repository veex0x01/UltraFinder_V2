package core

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

)

// BrowserProfile defines a browser emulation profile
type BrowserProfile struct {
	Name              string
	UserAgent         string
	AcceptLanguage    string
	AcceptEncoding    string
	Accept            string
	HTTP2Priority     bool
	HeaderOrder       []string
}

// EvasionConfig holds configuration for evasion techniques
type EvasionConfig struct {
	Profile           string        // "chrome", "firefox", "safari", "random"
	RateLimit         int           // requests per second per host
	JitterMs          int           // random delay 0-N milliseconds
	RetryOn429        bool          // retry on rate limit
	RetryOn503        bool          // retry on service unavailable
	MaxRetries        int           // maximum retry attempts
	BackoffFactor     int           // exponential backoff multiplier
	RespectRetryAfter bool          // honor Retry-After header
	RandomTLSProfile  bool          // randomize TLS fingerprint
	Timeout           time.Duration // request timeout
}

// DefaultEvasionConfig returns sensible defaults
func DefaultEvasionConfig() EvasionConfig {
	return EvasionConfig{
		Profile:           "chrome",
		RateLimit:         10,
		JitterMs:          500,
		RetryOn429:        true,
		RetryOn503:        true,
		MaxRetries:        3,
		BackoffFactor:     2,
		RespectRetryAfter: true,
		RandomTLSProfile:  true,
		Timeout:           15 * time.Second,
	}
}

// EvasionClient is an advanced HTTP client with WAF/CDN evasion capabilities
type EvasionClient struct {
	config      EvasionConfig
	profile     BrowserProfile
	rateLimiter *RateLimiter
	cookieJar   http.CookieJar
	mu          sync.RWMutex
}

// NewEvasionClient creates a new evasion-capable HTTP client
func NewEvasionClient(config EvasionConfig) (*EvasionClient, error) {
	profile := getBrowserProfile(config.Profile)
	
	jar, _ := NewCookieJar()
	
	return &EvasionClient{
		config:      config,
		profile:     profile,
		rateLimiter: NewRateLimiter(config.RateLimit),
		cookieJar:   jar,
	}, nil
}

// Get performs an HTTP GET with evasion techniques
func (c *EvasionClient) Get(ctx context.Context, targetURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return nil, err
	}
	
	return c.Do(req)
}

// Do executes an HTTP request with full evasion capabilities
func (c *EvasionClient) Do(req *http.Request) (*http.Response, error) {
	// Apply rate limiting
	host := req.URL.Hostname()
	c.rateLimiter.Wait(host)
	
	// Add jitter
	if c.config.JitterMs > 0 {
		jitter := time.Duration(rand.Intn(c.config.JitterMs)) * time.Millisecond
		time.Sleep(jitter)
	}
	
	// Apply browser profile headers
	c.applyHeaders(req)
	
	// Execute with retries
	return c.doWithRetry(req)
}

// doWithRetry handles request execution with exponential backoff
func (c *EvasionClient) doWithRetry(req *http.Request) (*http.Response, error) {
	var lastErr error
	backoff := 1 * time.Second
	
	for attempt := 0; attempt <= c.config.MaxRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= time.Duration(c.config.BackoffFactor)
		}
		
		// Clone request for retry
		reqClone := req.Clone(req.Context())
		c.applyHeaders(reqClone)
		
		// Create transport with uTLS
		transport, err := c.createTransport()
		if err != nil {
			return nil, err
		}
		
		client := &http.Client{
			Transport: transport,
			Jar:       c.cookieJar,
			Timeout:   c.config.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				// Follow up to 10 redirects
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				// Apply headers to redirect requests too
				c.applyHeaders(req)
				return nil
			},
		}
		
		resp, err := client.Do(reqClone)
		if err != nil {
			lastErr = err
			continue
		}
		
		// Check if we should retry
		shouldRetry := false
		if c.config.RetryOn429 && resp.StatusCode == 429 {
			shouldRetry = true
			// Check Retry-After header
			if c.config.RespectRetryAfter {
				if retryAfter := resp.Header.Get("Retry-After"); retryAfter != "" {
					if duration, err := time.ParseDuration(retryAfter + "s"); err == nil {
						backoff = duration
					}
				}
			}
		}
		if c.config.RetryOn503 && resp.StatusCode == 503 {
			shouldRetry = true
		}
		
		if !shouldRetry || attempt == c.config.MaxRetries {
			return resp, nil
		}
		
		// Drain and close body before retry
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	
	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

// createTransport creates a transport with uTLS for fingerprint randomization
func (c *EvasionClient) createTransport() (http.RoundTripper, error) {
	return &uTLSTransport{
		config: c.config,
		profile: c.profile,
	}, nil
}

// uTLSTransport implements http.RoundTripper with uTLS
type uTLSTransport struct {
	config  EvasionConfig
	profile BrowserProfile
}

func (t *uTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 1. Create uTLS Client Hello ID based on profile
	var helloID utls.ClientHelloID
	
	switch strings.ToLower(t.config.Profile) {
	case "chrome":
		helloID = utls.HelloChrome_120
	case "firefox":
		helloID = utls.HelloFirefox_120
	case "safari":
		helloID = utls.HelloSafari_16_0
	case "ios":
		helloID = utls.HelloIOS_13
	case "random":
		// Randomize popular fingerprints
		ids := []utls.ClientHelloID{
			utls.HelloChrome_120, 
			utls.HelloFirefox_120, 
			utls.HelloEdge_106,
			utls.HelloSafari_16_0,
		}
		helloID = ids[rand.Intn(len(ids))]
	default:
		helloID = utls.HelloChrome_120
	}

	// 2. Connect with uTLS
	addr := req.URL.Host
	if !strings.Contains(addr, ":") {
		addr += ":443"
	}

	// Use Dialer for strict timeout control
	dialer := &net.Dialer{
		Timeout: t.config.Timeout,
	}
	
	rawConn, err := dialer.DialContext(req.Context(), "tcp", addr)
	if err != nil {
		return nil, err
	}

	// 3. Handshake
	uConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         req.URL.Hostname(),
		InsecureSkipVerify: true,
	}, helloID)

	if err := uConn.Handshake(); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}

	// 4. Send Request (HTTP/1.1 for now, HTTP/2 support requires more work with framers)
	// We'll use a simple write/read for HTTP/1.1 over TLS
	// NOTE: This implementation is for HTTPS only.
	// For full HTTP/2 support, we'd need to use x/net/http2 with uTLS conn.
	// Current implementation forces HTTP/1.1 which is safer for many evasion scenarios anyway.
	
	// Re-write request for wire
	path := req.URL.Path
	if path == "" { path = "/" }
	if req.URL.RawQuery != "" { path += "?" + req.URL.RawQuery }

	// Write Request
	fmt.Fprintf(uConn, "%s %s HTTP/1.1\r\n", req.Method, path)
	fmt.Fprintf(uConn, "Host: %s\r\n", req.URL.Host)
	for k, v := range req.Header {
		for _, val := range v {
			fmt.Fprintf(uConn, "%s: %s\r\n", k, val)
		}
	}
	fmt.Fprintf(uConn, "\r\n")

	// Read Response
	return http.ReadResponse(bufio.NewReader(uConn), req)
}

// applyHeaders applies browser profile headers to request
func (c *EvasionClient) applyHeaders(req *http.Request) {
	// Set User-Agent
	req.Header.Set("User-Agent", c.profile.UserAgent)
	
	// Set Accept headers
	req.Header.Set("Accept", c.profile.Accept)
	req.Header.Set("Accept-Language", c.profile.AcceptLanguage)
	req.Header.Set("Accept-Encoding", c.profile.AcceptEncoding)
	
	// Add additional browser headers
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	
	// Referer spoofing (pretend to come from same domain)
	if req.Header.Get("Referer") == "" && req.URL.Scheme != "" {
		referer := fmt.Sprintf("%s://%s/", req.URL.Scheme, req.URL.Host)
		req.Header.Set("Referer", referer)
	}
}

// getBrowserProfile returns a browser profile
func getBrowserProfile(name string) BrowserProfile {
	profiles := map[string]BrowserProfile{
		"chrome": {
			Name:           "Chrome",
			UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
			AcceptLanguage: "en-US,en;q=0.9",
			AcceptEncoding: "gzip, deflate, br",
			HTTP2Priority:  true,
		},
		"firefox": {
			Name:           "Firefox",
			UserAgent:      "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
			Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			AcceptLanguage: "en-US,en;q=0.5",
			AcceptEncoding: "gzip, deflate, br",
			HTTP2Priority:  false,
		},
		"safari": {
			Name:           "Safari",
			UserAgent:      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
			Accept:         "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
			AcceptLanguage: "en-US,en;q=0.9",
			AcceptEncoding: "gzip, deflate, br",
			HTTP2Priority:  false,
		},
	}
	
	if prof, ok := profiles[strings.ToLower(name)]; ok {
		return prof
	}
	
	// Random or unknown - pick Chrome
	return profiles["chrome"]
}

// RateLimiter manages per-host rate limiting
type RateLimiter struct {
	limitPerSec int
	hostLimits  map[string]*hostLimiter
	mu          sync.Mutex
}

type hostLimiter struct {
	tokens    float64
	lastCheck time.Time
	mu        sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(requestsPerSec int) *RateLimiter {
	return &RateLimiter{
		limitPerSec: requestsPerSec,
		hostLimits:  make(map[string]*hostLimiter),
	}
}

// Wait blocks until a request can be made to the given host
func (r *RateLimiter) Wait(host string) {
	r.mu.Lock()
	limiter, exists := r.hostLimits[host]
	if !exists {
		limiter = &hostLimiter{
			tokens:    float64(r.limitPerSec),
			lastCheck: time.Now(),
		}
		r.hostLimits[host] = limiter
	}
	r.mu.Unlock()
	
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	
	// Token bucket algorithm
	now := time.Now()
	elapsed := now.Sub(limiter.lastCheck).Seconds()
	limiter.tokens += elapsed * float64(r.limitPerSec)
	if limiter.tokens > float64(r.limitPerSec) {
		limiter.tokens = float64(r.limitPerSec)
	}
	limiter.lastCheck = now
	
	// Wait if no tokens available
	for limiter.tokens < 1.0 {
		limiter.mu.Unlock()
		time.Sleep(100 * time.Millisecond)
		limiter.mu.Lock()
		
		now = time.Now()
		elapsed = now.Sub(limiter.lastCheck).Seconds()
		limiter.tokens += elapsed * float64(r.limitPerSec)
		if limiter.tokens > float64(r.limitPerSec) {
			limiter.tokens = float64(r.limitPerSec)
		}
		limiter.lastCheck = now
	}
	
	limiter.tokens -= 1.0
}

// NewCookieJar creates a simple cookie jar
func NewCookieJar() (http.CookieJar, error) {
	return &simpleCookieJar{
		cookies: make(map[string][]*http.Cookie),
	}, nil
}

type simpleCookieJar struct {
	cookies map[string][]*http.Cookie
	mu      sync.RWMutex
}

func (j *simpleCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies[u.Host] = cookies
}

func (j *simpleCookieJar) Cookies(u *url.URL) []*http.Cookie {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.cookies[u.Host]
}
