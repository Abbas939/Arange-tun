package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/mahdi-byte64/arange-tun/config"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"testing"
	"time"
)

func testKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
func TestPinnedHostKeyRejectsReplacement(t *testing.T) {
	key := testKey(t)
	other := testKey(t)
	cb, err := hostKeyCallback(&config.SSHConfig{HostKeySHA256: ssh.FingerprintSHA256(key.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("server:22", &net.TCPAddr{}, key.PublicKey()); err != nil {
		t.Fatal(err)
	}
	if cb("server:22", &net.TCPAddr{}, other.PublicKey()) == nil {
		t.Fatal("accepted replaced host key")
	}
}
func TestMissingKnownHostsFailsClosed(t *testing.T) {
	if _, err := hostKeyCallback(&config.SSHConfig{KnownHosts: t.TempDir() + "/missing"}); err == nil {
		t.Fatal("accepted missing trust store")
	}
}
func TestHandshakeHasDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, e := ln.Accept()
		if e == nil {
			defer c.Close()
			io.Copy(io.Discard, c)
		}
	}()
	start := time.Now()
	c, err := dial(context.Background(), ln.Addr().String(), &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.FixedHostKey(testKey(t).PublicKey()), Timeout: 80 * time.Millisecond})
	if c != nil {
		c.Close()
	}
	if err == nil {
		t.Fatal("stalled handshake succeeded")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("handshake timeout ignored")
	}
	<-done
}
