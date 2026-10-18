package manage

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/mahdi-byte64/arange-tun/internal/app"
	"github.com/mahdi-byte64/arange-tun/internal/tunnel/direct"
	"github.com/mahdi-byte64/arange-tun/internal/tunnel/naive"
	"strings"
)

// ValidateAdvanced validates the same config used by CLI and panel imports.
// No helper is executed, installed, or downloaded by parsing the form.
func ValidateAdvanced(raw string) error {
	if len(raw) > 128<<10 {
		return fmt.Errorf("configuration exceeds 128 KiB")
	}
	var c config.Config
	md, err := toml.Decode(raw, &c)
	if err != nil {
		return err
	}
	if len(md.Undecoded()) > 0 {
		return fmt.Errorf("unknown configuration key: %s", md.Undecoded()[0])
	}
	if c.SSH.Role != "" || c.Packet.Role != "" || c.WireGuard.Role != "" || c.Hedioum.Role != "" {
		return fmt.Errorf("use the dedicated form for this engine")
	}
	if c.Direct.Enabled() {
		if c.Server.BindAddr != "" || c.Client.RemoteAddr != "" || c.Server.Naive.Enabled() || c.Client.Naive.Enabled() || c.Server.Xray.Enabled() || c.Client.Xray.Enabled() {
			return fmt.Errorf("direct requires its own configuration")
		}
		if len(c.Direct.Token) < 32 || strings.Contains(c.Direct.Token, "REPLACE_") {
			return fmt.Errorf("use a random token of at least 32 characters")
		}
		dc := direct.ConfigFromTable(c.Direct)
		return dc.Validate()
	}
	if !c.Server.Naive.Enabled() && !c.Client.Naive.Enabled() && !c.Server.Xray.Enabled() && !c.Client.Xray.Enabled() {
		return fmt.Errorf("expected a direct tunnel or managed Naive/Xray reverse configuration")
	}
	token := c.Server.Token
	if c.Client.RemoteAddr != "" {
		token = c.Client.Token
	}
	if len(token) < 32 || strings.Contains(token, "REPLACE_") {
		return fmt.Errorf("use a random token of at least 32 characters")
	}
	if err := naive.Validate(&c); err != nil {
		return err
	}
	return naive.ValidateXray(&c)
}

func ImportAdvanced(name, raw string, replace bool) error {
	name = strings.TrimSpace(name)
	if !validName(name) || name == "." || name == ".." {
		return fmt.Errorf("invalid tunnel name")
	}
	if err := ValidateAdvanced(raw); err != nil {
		return err
	}
	exists := fileExists(app.ConfigPath(name))
	if exists && !replace {
		return fmt.Errorf("tunnel exists; choose edit explicitly")
	}
	if !exists && replace {
		return fmt.Errorf("no tunnel with that name to edit")
	}
	if exists {
		if _, err := TakeSnapshot("pre-advanced-edit"); err != nil {
			return err
		}
	}
	_, err := saveGeneratedTunnel(name, raw)
	return err
}
