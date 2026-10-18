package cmd

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"github.com/BurntSushi/toml"
	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/utils/network"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestManagedCertificateRenewalReloadsUnchangedTOML(t *testing.T) {
	dir := t.TempDir()
	cert, err := network.GenerateSelfSigned("tunnel.example.com")
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile, binary := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"), filepath.Join(dir, "helper")
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600)
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0600)
	os.WriteFile(binary, []byte("test helper; never executed"), 0600)
	cfg := config.Config{Server: config.ServerConfig{BindAddr: "127.0.0.1:19090", Transport: config.TCP, Token: "long-test-token", Xray: config.XrayServerConfig{Binary: binary, Mode: "xhttp", Listen: "127.0.0.1:18443", UUID: "fde7d575-641f-4a41-bb9c-c5b3bb05e580", ServerName: "tunnel.example.com", Path: "/test", Certificate: certFile, Key: keyFile}}}
	file := filepath.Join(dir, "tunnel.toml")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	err = toml.NewEncoder(f).Encode(cfg)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	current, err := loadConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	applyDefaults(current)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *config.Config, 1)
	go func() { done <- awaitConfigChange(ctx, file, current) }()
	// Allow the watcher to record its initial certificate fingerprint.
	time.Sleep(100 * time.Millisecond)
	renewed := *cert.Leaf
	renewed.SerialNumber = new(big.Int).Add(cert.Leaf.SerialNumber, big.NewInt(1))
	der, err := x509.CreateCertificate(rand.Reader, &renewed, &renewed, cert.PrivateKey.(crypto.Signer).Public(), cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case next := <-done:
		if next == nil {
			t.Fatal("watcher stopped instead of reloading")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a valid certificate renewal did not reload the unchanged TOML")
	}
}
