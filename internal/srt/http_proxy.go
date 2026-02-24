package srt

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type HTTPProxyOptions struct {
	Filter            func(port int, host string) bool
	GetMitmSocketPath func(host string) string
}

type HTTPProxyServer struct {
	server   *http.Server
	listener net.Listener
}

func StartHTTPProxyServer(ctx context.Context, opts HTTPProxyOptions) (*HTTPProxyServer, int, error) {
	h := &httpProxyHandler{opts: opts}
	server := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 30 * time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}

	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			Debugf("HTTP proxy serve error: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		// Use a detached timeout so shutdown can finish even though ctx is done.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			Debugf("HTTP proxy shutdown error: %v", err)
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	return &HTTPProxyServer{server: server, listener: ln}, port, nil
}

func (s *HTTPProxyServer) Close(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *HTTPProxyServer) Addr() net.Addr {
	return s.listener.Addr()
}

type httpProxyHandler struct {
	opts HTTPProxyOptions
}

func (h *httpProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.EqualFold(r.Method, http.MethodConnect) {
		h.handleConnect(w, r)
		return
	}

	h.handleHTTP(w, r)
}

func (h *httpProxyHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, ok := splitHostPortWithDefault(r.Host, 443)
	if !ok {
		http.Error(w, "Bad CONNECT request", http.StatusBadRequest)
		return
	}

	if h.opts.Filter != nil && !h.opts.Filter(port, host) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "Connection blocked by network allowlist")
		return
	}

	// After we send "200 Connection Established", the connection stops being HTTP
	// and becomes a raw TCP tunnel (typically carrying TLS bytes). Go's ResponseWriter
	// only supports writing responses — it can't read raw bytes from the client, and
	// the HTTP server would try to parse the TLS handshake as the next HTTP request.
	// Hijack() gives us the raw net.Conn so we can do bidirectional byte copying.
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}

	mitmSocket := ""
	if h.opts.GetMitmSocketPath != nil {
		mitmSocket = h.opts.GetMitmSocketPath(host)
	}

	if mitmSocket != "" {
		h.handleConnectViaMITM(clientConn, mitmSocket, host, port)
		return
	}

	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 10*time.Second)
	if err != nil {
		_, _ = io.WriteString(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		_ = clientConn.Close()
		return
	}

	_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	proxyBidirectional(clientConn, targetConn)
}

func (h *httpProxyHandler) handleConnectViaMITM(clientConn net.Conn, socketPath, host string, port int) {
	mitmConn, err := net.DialTimeout("unix", socketPath, 10*time.Second)
	if err != nil {
		_, _ = io.WriteString(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		_ = clientConn.Close()
		return
	}

	_, _ = fmt.Fprintf(mitmConn, "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n", host, port, host, port)
	br := bufio.NewReader(mitmConn)
	line, err := br.ReadString('\n')
	if err != nil {
		_, _ = io.WriteString(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		_ = clientConn.Close()
		_ = mitmConn.Close()
		return
	}

	if !strings.Contains(line, " 200 ") {
		_, _ = io.WriteString(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		_ = clientConn.Close()
		_ = mitmConn.Close()
		return
	}

	for {
		h, err := br.ReadString('\n')
		if err != nil {
			_, _ = io.WriteString(clientConn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
			_ = clientConn.Close()
			_ = mitmConn.Close()
			return
		}
		if h == "\r\n" {
			break
		}
	}

	_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	proxyBidirectionalBuffered(clientConn, mitmConn, br)
}

func (h *httpProxyHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	host, port := extractRequestHostPort(r)
	if host == "" {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	if h.opts.Filter != nil && !h.opts.Filter(port, host) {
		w.Header().Set("X-Proxy-Error", "blocked-by-allowlist")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "Connection blocked by network allowlist")
		return
	}

	mitmSocket := ""
	if h.opts.GetMitmSocketPath != nil {
		mitmSocket = h.opts.GetMitmSocketPath(host)
	}

	if mitmSocket != "" {
		h.forwardViaMITM(w, r, mitmSocket)
		return
	}

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	if !outReq.URL.IsAbs() {
		outReq.URL.Scheme = "http"
		outReq.URL.Host = r.Host
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	resp, err := transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyResponse(w, resp)
}

func (h *httpProxyHandler) forwardViaMITM(w http.ResponseWriter, r *http.Request, socketPath string) {
	conn, err := net.DialTimeout("unix", socketPath, 10*time.Second)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer conn.Close()

	if err := r.WriteProxy(conn); err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), r)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyResponse(w, resp)
}

func copyResponse(w http.ResponseWriter, resp *http.Response) {
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func proxyBidirectional(a, b net.Conn) {
	go func() {
		_, _ = io.Copy(a, b)
		_ = a.Close()
		_ = b.Close()
	}()
	go func() {
		_, _ = io.Copy(b, a)
		_ = a.Close()
		_ = b.Close()
	}()
}

func proxyBidirectionalBuffered(clientConn, serverConn net.Conn, serverReader *bufio.Reader) {
	go func() {
		if serverReader.Buffered() > 0 {
			_, _ = io.Copy(clientConn, serverReader)
		}
		_, _ = io.Copy(clientConn, serverConn)
		_ = clientConn.Close()
		_ = serverConn.Close()
	}()
	go func() {
		_, _ = io.Copy(serverConn, clientConn)
		_ = clientConn.Close()
		_ = serverConn.Close()
	}()
}

func extractRequestHostPort(r *http.Request) (string, int) {
	if r.URL != nil {
		h := r.URL.Hostname()
		if h != "" {
			p := 80
			if strings.EqualFold(r.URL.Scheme, "https") {
				p = 443
			}
			if r.URL.Port() != "" {
				if v, err := strconv.Atoi(r.URL.Port()); err == nil {
					p = v
				}
			}
			return h, p
		}
	}

	h, p, ok := splitHostPortWithDefault(r.Host, 80)
	if !ok {
		return "", 0
	}
	return h, p
}

func splitHostPortWithDefault(hostPort string, defaultPort int) (string, int, bool) {
	hostPort = strings.TrimSpace(hostPort)
	if hostPort == "" {
		return "", 0, false
	}

	if strings.Contains(hostPort, ":") {
		host, portStr, err := net.SplitHostPort(hostPort)
		if err == nil {
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return "", 0, false
			}
			return host, port, true
		}

		parts := strings.Split(hostPort, ":")
		if len(parts) == 2 {
			port, err := strconv.Atoi(parts[1])
			if err != nil {
				return "", 0, false
			}
			return parts[0], port, true
		}
	}

	return hostPort, defaultPort, true
}
