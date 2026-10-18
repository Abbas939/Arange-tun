// Package ssh is a client-only VPN-egress tunnel over SSH. It dials an SSH
// server abroad with a username and password and exposes a local SOCKS5 proxy
// whose connections are dialed from the server side (SSH dynamic forwarding), so
// a panel outbound pointed at the SOCKS5 leaves by the server's IP. It keeps the
// SSH connection up, reconnecting with backoff if it drops.
//
// Server identity is checked against an explicit SHA256 pin or known_hosts.
package ssh

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/metrics"
	"github.com/mahdi-byte64/arange-tun/internal/socksproxy"
)

// RunClient keeps an SSH connection up and serves a SOCKS5 proxy through it
// until ctx ends.
func RunClient(ctx context.Context, sc *config.SSHConfig, logger *logrus.Logger) {
	host := sc.Host
	if host == "" {
		logger.Fatalf("ssh: the server host is required")
		return
	}
	port := sc.Port
	if port <= 0 {
		port = 22
	}
	if sc.User == "" {
		logger.Fatalf("ssh: the username is required")
		return
	}
	bind := sc.SocksBind
	if bind == "" {
		bind = "127.0.0.1"
	}
	if ip := net.ParseIP(bind); ip == nil || !ip.IsLoopback() {
		logger.Error("ssh: the unauthenticated SOCKS listener must use a loopback IP")
		return
	}
	if sc.SocksPort <= 0 {
		logger.Fatalf("ssh: a SOCKS5 port is required")
		return
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(bind, strconv.Itoa(sc.SocksPort)))
	if err != nil {
		logger.Fatalf("ssh: cannot open the SOCKS5 port %d: %v", sc.SocksPort, err)
		return
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		ln.Close()
		metrics.ClearPeer()
	}()

	server := net.JoinHostPort(host, strconv.Itoa(port))
	verify, err := hostKeyCallback(sc)
	if err != nil {
		logger.Errorf("ssh: %v", err)
		return
	}
	auth := []ssh.AuthMethod{ssh.Password(sc.Password)}
	if sc.IdentityFile != "" {
		pem, err := os.ReadFile(sc.IdentityFile)
		if err != nil {
			logger.Errorf("ssh: cannot read identity file: %v", err)
			return
		}
		key, err := ssh.ParsePrivateKey(pem)
		if err != nil {
			logger.Errorf("ssh: cannot parse identity file: %v", err)
			return
		}
		auth = []ssh.AuthMethod{ssh.PublicKeys(key)}
	}
	cfg := &ssh.ClientConfig{
		User:            sc.User,
		Auth:            auth,
		HostKeyCallback: verify,
		Timeout:         15 * time.Second,
	}

	logger.Infof("ssh client: connecting to %s@%s, SOCKS5 on %s", sc.User, server, ln.Addr())
	runWithReconnect(ctx, server, cfg, ln, logger)
}

// runWithReconnect (re)establishes the SSH connection and serves SOCKS5 over it,
// backing off between attempts. Each successful connection serves until it drops
// or ctx ends.
func runWithReconnect(ctx context.Context, server string, cfg *ssh.ClientConfig, ln net.Listener, logger *logrus.Logger) {
	// Exactly one accept loop survives every reconnect. A request snapshots the
	// current client; old accept loops must never steal work from a new session.
	var mu sync.RWMutex
	var current *ssh.Client
	go socksproxy.Serve(ctx, ln, func(dctx context.Context, network, address string) (net.Conn, error) {
		mu.RLock()
		c := current
		mu.RUnlock()
		if c == nil {
			return nil, fmt.Errorf("SSH connection is not ready")
		}
		return c.DialContext(dctx, network, address)
	}, logger)
	defer func() { mu.Lock(); current = nil; mu.Unlock() }()
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		client, err := dial(ctx, server, cfg)
		if err != nil {
			metrics.ClearPeer()
			logger.Warnf("ssh client: connect failed: %v (retrying in %s)", err, backoff)
			if !sleepCtx(ctx, backoff) {
				return
			}
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		metrics.ReportPeer(server)
		logger.Infof("ssh client: connected to %s", server)

		// A SOCKS dial opens a direct-tcpip channel from the SSH server to the
		// target, so the traffic egresses at the server.
		mu.Lock()
		current = client
		mu.Unlock()

		// Block until the connection drops or ctx ends.
		waitClosed(ctx, client)
		mu.Lock()
		current = nil
		mu.Unlock()
		client.Close()
		metrics.ClearPeer()
		if ctx.Err() != nil {
			return
		}
		logger.Warnf("ssh client: connection lost, reconnecting...")
	}
}

func dial(ctx context.Context, server string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	d := net.Dialer{Timeout: cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	c, chans, reqs, err := ssh.NewClientConn(conn, server, cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// waitClosed returns when the SSH connection closes or ctx ends. A keepalive
// request doubles as the liveness probe.
func waitClosed(ctx context.Context, client *ssh.Client) {
	closed := make(chan struct{})
	go func() {
		client.Wait() // returns when the underlying connection is gone
		close(closed)
	}()
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-closed:
			return
		case <-ticker.C:
			probe := make(chan error, 1)
			go func() { _, _, err := client.SendRequest("keepalive@arange-tun", true, nil); probe <- err }()
			timer := time.NewTimer(10 * time.Second)
			select {
			case err := <-probe:
				timer.Stop()
				if err != nil {
					return
				}
			case <-timer.C:
				client.Close()
				return
			case <-ctx.Done():
				timer.Stop()
				client.Close()
				return
			}
		}
	}
}

func hostKeyCallback(sc *config.SSHConfig) (ssh.HostKeyCallback, error) {
	if sc.HostKeySHA256 != "" {
		return func(host string, remote net.Addr, key ssh.PublicKey) error {
			if subtle.ConstantTimeCompare([]byte(ssh.FingerprintSHA256(key)), []byte(sc.HostKeySHA256)) != 1 {
				return fmt.Errorf("SSH host key mismatch for %s", host)
			}
			return nil
		}, nil
	}
	path := sc.KnownHosts
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(home, ".ssh", "known_hosts")
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("configure host_key_sha256 or a trusted known_hosts file: %w", err)
	}
	return cb, nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
