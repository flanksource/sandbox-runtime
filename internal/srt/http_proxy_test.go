package srt

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestHTTPProxy_CONNECTFiltering(t *testing.T) {
	ctx := context.Background()
	proxy, port, err := StartHTTPProxyServer(ctx, HTTPProxyOptions{
		Filter: func(_ int, host string) bool {
			return host == "localhost"
		},
	})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer proxy.Close(ctx)

	statusAllowed, err := proxyConnectStatus(port, "localhost", 1)
	if err != nil {
		t.Fatalf("allowed connect request failed: %v", err)
	}
	if statusAllowed == 403 {
		t.Fatalf("expected localhost to pass filter (non-403), got %d", statusAllowed)
	}

	statusBlocked, err := proxyConnectStatus(port, "example.com", 443)
	if err != nil {
		t.Fatalf("blocked connect request failed: %v", err)
	}
	if statusBlocked != 403 {
		t.Fatalf("expected blocked status 403, got %d", statusBlocked)
	}
}

func TestHTTPProxy_HTTPFiltering(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()

	targetURL, _ := url.Parse(target.URL)
	allowedHost := targetURL.Hostname()

	ctx := context.Background()
	proxy, port, err := StartHTTPProxyServer(ctx, HTTPProxyOptions{
		Filter: func(_ int, host string) bool {
			return host == allowedHost
		},
	})
	if err != nil {
		t.Fatalf("start proxy: %v", err)
	}
	defer proxy.Close(ctx)

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("proxy GET allowed host failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 from allowed host, got %d", resp.StatusCode)
	}

	blockedURL := strings.Replace(target.URL, allowedHost, "example.com", 1)
	resp2, err := client.Get(blockedURL)
	if err == nil {
		defer resp2.Body.Close()
		if resp2.StatusCode != 403 {
			t.Fatalf("expected 403 for blocked host, got %d", resp2.StatusCode)
		}
	}
}

func proxyConnectStatus(proxyPort int, host string, port int) (int, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort), 2*time.Second)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := fmt.Fprintf(conn, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port); err != nil {
		return 0, err
	}

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return 0, err
	}
	var status int
	_, _ = fmt.Sscanf(line, "HTTP/1.1 %d", &status)
	if status == 0 {
		_, _ = fmt.Sscanf(line, "HTTP/1.0 %d", &status)
	}
	if status == 0 {
		return 0, fmt.Errorf("unable to parse status line: %q", line)
	}
	return status, nil
}
