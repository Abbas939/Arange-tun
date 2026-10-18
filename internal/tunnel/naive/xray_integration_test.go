package naive

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/socks"
	"github.com/mahdi-byte64/arange-tun/internal/utils/network"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func freeAddress(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

// This optional test runs official Xray rather than mocking its JSON contract.
func TestOfficialXrayXHTTPRoundTripAndDestinationRestriction(t *testing.T) {
	testOfficialXray(t, "xhttp")
}

func TestOfficialXrayRealityRoundTripAndDestinationRestriction(t *testing.T) {
	testOfficialXray(t, "reality")
}

func testOfficialXray(t *testing.T, mode string) {
	binary := os.Getenv("ARANGE_XRAY_BINARY")
	if binary == "" {
		t.Skip("set ARANGE_XRAY_BINARY to test the official helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	dir := t.TempDir()
	cert, err := network.GenerateSelfSigned("localhost")
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	public := freeAddress(t)
	sc := &config.ServerConfig{BindAddr: echo.Addr().String(), Transport: config.TCP, Xray: config.XrayServerConfig{Binary: binary, Listen: public, Mode: "xhttp", UUID: "fde7d575-641f-4a41-bb9c-c5b3bb05e580", ServerName: "localhost", Path: "/private-test", Certificate: certFile, Key: keyFile}}
	var realityKey *ecdh.PrivateKey
	if mode == "reality" {
		// Use a local TLS 1.3/H2 cover so this test needs no third-party host.
		cover := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("cover")) }))
		cover.EnableHTTP2 = true
		cover.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
		cover.StartTLS()
		defer cover.Close()
		realityKey, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sc.Xray.Mode = mode
		sc.Xray.Path = ""
		sc.Xray.Certificate = ""
		sc.Xray.Key = ""
		sc.Xray.PrivateKey = base64.RawURLEncoding.EncodeToString(realityKey.Bytes())
		sc.Xray.ShortID = "0123456789abcdef"
		sc.Xray.Target = cover.Listener.Addr().String()
	}
	sh, err := StartXrayServer(ctx, sc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sh.Close()
	cc := &config.ClientConfig{RemoteAddr: echo.Addr().String(), Transport: config.TCP, Xray: config.XrayClientConfig{Binary: binary, Server: public, Mode: "xhttp", UUID: sc.Xray.UUID, ServerName: "localhost", Path: sc.Xray.Path, CAFile: certFile}}
	if mode == "reality" {
		cc.Xray.Mode = mode
		cc.Xray.CAFile = ""
		cc.Xray.ShortID = sc.Xray.ShortID
		cc.Xray.PublicKey = base64.RawURLEncoding.EncodeToString(realityKey.PublicKey().Bytes())
	}
	ch, err := StartXrayClient(ctx, cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	dial := func(target string) (net.Conn, error) {
		c, e := net.DialTimeout("tcp", ch.addr, time.Second)
		if e != nil {
			return nil, e
		}
		c.SetDeadline(time.Now().Add(8 * time.Second))
		host, port, _ := net.SplitHostPort(target)
		var p int
		fmt.Sscanf(port, "%d", &p)
		if e = socks.Negotiate(c, "", "", host, p); e != nil {
			c.Close()
			return nil, e
		}
		return c, nil
	}
	c, err := dial(echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := []byte("verified XHTTP traffic")
	if _, err = c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatal("payload mismatch")
	}
	// The private helper must not become an unrestricted local proxy.
	blockedTarget, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blockedTarget.Close()
	reached := make(chan struct{}, 1)
	go func() {
		c, e := blockedTarget.Accept()
		if e == nil {
			reached <- struct{}{}
			c.Close()
		}
	}()
	forbidden, err := dial(blockedTarget.Addr().String())
	if err == nil {
		defer forbidden.Close()
		forbidden.Write([]byte("x"))
		var b [1]byte
		if _, err = forbidden.Read(b[:]); err == nil {
			t.Fatal("unauthorized destination carried data")
		}
	}
	select {
	case <-reached:
		t.Fatal("helper reached an unauthorized listening destination")
	case <-time.After(150 * time.Millisecond):
	}
}
