package probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"
)

// Results holds probe data
type Results struct {
	DNS     map[string][]string
	Robots  string
	Magento string
}

// Run executes DNS and HTTP probes concurrently
func Run(targetURL string, hostname string, userAgent string, maxWait time.Duration) *Results {
	results := &Results{
		DNS: make(map[string][]string),
	}

	domain := strings.TrimPrefix(hostname, "www.")

	var wg sync.WaitGroup

	// DNS lookups
	wg.Add(1)
	go func() {
		defer wg.Done()
		resolveDNS(hostname, domain, results, maxWait)
	}()

	// robots.txt
	wg.Add(1)
	go func() {
		defer wg.Done()
		body, err := httpGet(fmt.Sprintf("%s/robots.txt", targetURL), userAgent, maxWait)
		if err == nil && len(body) < 100000 {
			results.Robots = body
		}
	}()

	// /magento_version
	wg.Add(1)
	go func() {
		defer wg.Done()
		body, err := httpGet(fmt.Sprintf("%s/magento_version", targetURL), userAgent, maxWait)
		if err == nil && len(body) < 100000 {
			results.Magento = body
		}
	}()

	wg.Wait()
	return results
}

func resolveDNS(hostname, domain string, results *Results, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	resolver := &net.Resolver{}

	var wg sync.WaitGroup

	// CNAME
	wg.Add(1)
	go func() {
		defer wg.Done()
		cname, err := resolver.LookupCNAME(ctx, hostname)
		if err == nil && cname != "" {
			results.DNS["cname"] = []string{strings.TrimSuffix(cname, ".")}
		}
	}()

	// NS
	wg.Add(1)
	go func() {
		defer wg.Done()
		ns, err := resolver.LookupNS(ctx, domain)
		if err == nil {
			for _, n := range ns {
				results.DNS["ns"] = append(results.DNS["ns"], n.Host)
			}
		}
	}()

	// MX
	wg.Add(1)
	go func() {
		defer wg.Done()
		mx, err := resolver.LookupMX(ctx, domain)
		if err == nil {
			for _, m := range mx {
				results.DNS["mx"] = append(results.DNS["mx"],
					fmt.Sprintf("%d %s", m.Pref, m.Host))
			}
		}
	}()

	// TXT
	wg.Add(1)
	go func() {
		defer wg.Done()
		txt, err := resolver.LookupTXT(ctx, domain)
		if err == nil {
			results.DNS["txt"] = txt
		}
	}()

	// SOA via miekg/dns
	wg.Add(1)
	go func() {
		defer wg.Done()
		soa := lookupSOA(domain, timeout)
		if soa != "" {
			results.DNS["soa"] = []string{soa}
		}
	}()

	wg.Wait()
}

func lookupSOA(domain string, timeout time.Duration) string {
	c := new(mdns.Client)
	c.Timeout = timeout

	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(domain), mdns.TypeSOA)
	m.RecursionDesired = true

	// Use system default resolver or Google DNS
	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return ""
	}

	for _, ans := range r.Answer {
		if soa, ok := ans.(*mdns.SOA); ok {
			return fmt.Sprintf("%s %s %d %d %d %d %d",
				soa.Ns, soa.Mbox, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl)
		}
	}

	return ""
}

func httpGet(url string, userAgent string, timeout time.Duration) (string, error) {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(body), nil
}
