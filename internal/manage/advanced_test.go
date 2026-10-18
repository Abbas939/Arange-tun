package manage

import (
	"strings"
	"testing"
)

func TestAdvancedDirectValidation(t *testing.T) {
	good := `[direct]
role="iran"
addr="127.0.0.1:8443"
token="0123456789abcdef0123456789abcdef"
transport="stealth"
ports=["127.0.0.1:8080=127.0.0.1:80"]
`
	if err := ValidateAdvanced(good); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"weak-token":   strings.ReplaceAll(good, "0123456789abcdef0123456789abcdef", "short"),
		"unknown-key":  good + "typo = true\n",
		"mixed-engine": good + "\n[server]\nbind_addr=\"127.0.0.1:9000\"\n",
		"bad-carrier":  strings.ReplaceAll(good, "stealth", "imaginary"),
	} {
		t.Run(name, func(t *testing.T) {
			if ValidateAdvanced(bad) == nil {
				t.Fatal("accepted unsafe config")
			}
		})
	}
}
func TestSSHRenderPreservesExplicitPin(t *testing.T) {
	s := sshRenderClient("test", "server", 22, "user", "password", "127.0.0.1", 1080, "SHA256:trusted")
	if !strings.Contains(s, `host_key_sha256 = "SHA256:trusted"`) {
		t.Fatal("pin was discarded")
	}
}

func TestTunnelPathsRejectTraversalBeforeIO(t *testing.T) {
	for _, name := range []string{"../outside", "a/b", `a\b`, "bad\nname"} {
		if _, err := LoadTunnelConfig(name); err == nil {
			t.Fatalf("read accepted %q", name)
		}
		if _, err := saveGeneratedTunnel(name, "[ssh]"); err == nil {
			t.Fatalf("write accepted %q", name)
		}
		if err := Delete(name); err == nil {
			t.Fatalf("delete accepted %q", name)
		}
	}
}
