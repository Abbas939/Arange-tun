package network

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

func TestTLSObfsAuthenticatesBothPeers(t *testing.T) {
	for _, same := range []bool{true, false} {
		t.Run(map[bool]string{true: "same-token", false: "wrong-token"}[same], func(t *testing.T) {
			cfg, err := SelfSignedTLSConfig()
			if err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			result := make(chan error, 1)
			go func() {
				raw, e := ln.Accept()
				if e != nil {
					result <- e
					return
				}
				defer raw.Close()
				c, e := TLSServerConn(raw, cfg, time.Second, "right-token")
				if e == nil {
					_, e = c.Write([]byte("ok"))
				}
				result <- e
			}()
			raw, err := net.Dial("tcp", ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			token := "right-token"
			if !same {
				token = "wrong-token"
			}
			c, err := TLSClientConn(raw, "localhost", time.Second, token)
			if same {
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				var b [2]byte
				if _, err = io.ReadFull(c, b[:]); err != nil {
					t.Fatal(err)
				}
				if string(b[:]) != "ok" {
					t.Fatal("bad payload")
				}
			} else if err == nil {
				c.Close()
				t.Fatal("accepted wrong token")
			}
			if e := <-result; same && e != nil {
				t.Fatal(e)
			}
		})
	}
}

// A peer that only completes ordinary TLS must never reach the tunnel protocol.
func TestTLSOnlyImpostorCannotAuthenticate(t *testing.T) {
	cfg, _ := SelfSignedTLSConfig()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
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
			c.SetDeadline(time.Now().Add(150 * time.Millisecond))
			io.Copy(io.Discard, c)
		}
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c, err := TLSClientConn(raw, "localhost", 200*time.Millisecond, "secret-token")
	if err == nil {
		c.Close()
		t.Fatal("TLS-only peer impersonated authenticated server")
	}
	<-done
}
