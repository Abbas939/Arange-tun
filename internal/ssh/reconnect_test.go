package ssh

import (
	"context"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

type countedListener struct {
	net.Listener
	calls atomic.Int32
}

func (l *countedListener) Accept() (net.Conn, error) { l.calls.Add(1); return l.Listener.Accept() }

func TestReconnectKeepsExactlyOneSOCKSAcceptor(t *testing.T) {
	key := testKey(t)
	sc := &ssh.ServerConfig{NoClientAuth: true}
	sc.AddHostKey(key)
	server, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	connections := make(chan *ssh.ServerConn, 8)
	go func() {
		for {
			c, e := server.Accept()
			if e != nil {
				return
			}
			go func() {
				conn, chans, reqs, e := ssh.NewServerConn(c, sc)
				if e != nil {
					c.Close()
					return
				}
				connections <- conn
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					ch.Reject(ssh.Prohibited, "unused")
				}
			}()
		}
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener := &countedListener{Listener: ln}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runWithReconnect(ctx, server.Addr().String(), &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.FixedHostKey(key.PublicKey()), Timeout: time.Second}, listener, logrus.New())
	}()
	defer func() {
		cancel()
		ln.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("reconnect worker did not stop")
		}
	}()
	for i := 0; i < 3; i++ {
		select {
		case conn := <-connections:
			conn.Close()
		case <-time.After(3 * time.Second):
			t.Fatal("SSH did not reconnect")
		}
	}
	deadline := time.Now().Add(time.Second)
	for listener.calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls := listener.calls.Load(); calls != 1 {
		t.Fatalf("%d competing SOCKS acceptors after reconnects, want 1", calls)
	}
}
