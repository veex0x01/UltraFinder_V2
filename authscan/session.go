package authscan

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuthSession represents an authenticated session context
type AuthSession struct {
	Name    string            // "admin", "user", "guest"
	Role    string            // Privilege level
	Cookies map[string]string
	Headers map[string]string // Authorization headers
	Token   string            // Bearer/JWT token
}

// SessionManager manages multiple authentication sessions
type SessionManager struct {
	sessions map[string]*AuthSession
	client   *http.Client
	mu       sync.RWMutex
}

// NewSessionManager creates a new SessionManager
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*AuthSession),
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects
			},
		},
	}
}

// AddSession registers a session context
func (sm *SessionManager) AddSession(session AuthSession) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions[session.Name] = &session
}

// GetSession retrieves a session by name
func (sm *SessionManager) GetSession(name string) *AuthSession {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[name]
}

// ParseSessionFromFlags parses session headers from CLI flags
// Format: "Cookie: session=abc" or "Authorization: Bearer xyz"
func ParseSessionFromFlags(name, headers string) AuthSession {
	session := AuthSession{
		Name:    name,
		Cookies: make(map[string]string),
		Headers: make(map[string]string),
	}

	parts := strings.SplitN(headers, ": ", 2)
	if len(parts) == 2 {
		headerName := parts[0]
		headerValue := parts[1]

		if strings.EqualFold(headerName, "Cookie") {
			// Parse cookie string
			for _, cookie := range strings.Split(headerValue, "; ") {
				kv := strings.SplitN(cookie, "=", 2)
				if len(kv) == 2 {
					session.Cookies[kv[0]] = kv[1]
				}
			}
		} else if strings.EqualFold(headerName, "Authorization") {
			session.Token = headerValue
			session.Headers["Authorization"] = headerValue
		} else {
			session.Headers[headerName] = headerValue
		}
	}

	return session
}

// ReplayAs replays a request using a different session
func (sm *SessionManager) ReplayAs(originalReq *http.Request, sessionName string) (*http.Response, error) {
	session := sm.GetSession(sessionName)
	if session == nil {
		return nil, fmt.Errorf("session '%s' not found", sessionName)
	}

	// Clone the request
	newReq, err := http.NewRequest(originalReq.Method, originalReq.URL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Copy original headers (except auth-related)
	for k, v := range originalReq.Header {
		lowerK := strings.ToLower(k)
		if lowerK != "cookie" && lowerK != "authorization" {
			newReq.Header[k] = v
		}
	}

	// Apply session cookies
	for name, value := range session.Cookies {
		newReq.AddCookie(&http.Cookie{Name: name, Value: value})
	}

	// Apply session headers
	for name, value := range session.Headers {
		newReq.Header.Set(name, value)
	}

	return sm.client.Do(newReq)
}

// SendRequest sends a request with session context applied
func (sm *SessionManager) SendRequest(method, url, sessionName string, body io.Reader) (*http.Response, error) {
	session := sm.GetSession(sessionName)

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	if session != nil {
		for name, value := range session.Cookies {
			req.AddCookie(&http.Cookie{Name: name, Value: value})
		}
		for name, value := range session.Headers {
			req.Header.Set(name, value)
		}
	}

	return sm.client.Do(req)
}

// SendUnauthenticated sends a request with no session
func (sm *SessionManager) SendUnauthenticated(method, url string) (*http.Response, error) {
	return sm.SendRequest(method, url, "__none__", nil)
}
