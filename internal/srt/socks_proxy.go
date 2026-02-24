package srt

import (
	"context"
	"net"
	"time"

	socks5 "github.com/armon/go-socks5"
)

type SocksProxyOptions struct {
	Filter func(port int, host string) bool
}

type SocksProxyServer struct {
	server *socks5.Server
	ln     net.Listener
}

type socksRuleSet struct {
	filter func(port int, host string) bool
}

func (r socksRuleSet) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	if r.filter == nil {
		return ctx, true
	}
	host := ""
	if req.DestAddr != nil {
		if req.DestAddr.FQDN != "" {
			host = req.DestAddr.FQDN
		} else if req.DestAddr.IP != nil {
			host = req.DestAddr.IP.String()
		}
	}
	if host == "" {
		return ctx, false
	}
	return ctx, r.filter(req.DestAddr.Port, host)
}

func StartSocksProxyServer(opts SocksProxyOptions) (*SocksProxyServer, int, error) {
	cfg := &socks5.Config{
		Rules: socksRuleSet{filter: opts.Filter},
	}
	server, err := socks5.New(cfg)
	if err != nil {
		return nil, 0, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, 0, err
	}
	go func() {
		if err := server.Serve(ln); err != nil {
			Debugf("SOCKS proxy serve error: %v", err)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return &SocksProxyServer{server: server, ln: ln}, port, nil
}

func (s *SocksProxyServer) Close() error {
	if s == nil || s.ln == nil {
		return nil
	}
	return s.ln.Close()
}

func (s *SocksProxyServer) Addr() net.Addr {
	if s == nil || s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

func (s *SocksProxyServer) Unref() {
	// No-op in Go (there is no net.Listener unref equivalent).
}

func (s *SocksProxyServer) WaitUntilClosed(timeout time.Duration) {
	if s == nil || s.ln == nil {
		return
	}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", s.ln.Addr().String(), 100*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(50 * time.Millisecond)
	}
}
