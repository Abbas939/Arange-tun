//go:build !linux

package manage

import "fmt"

func lockUpdate() (func(), error) { return nil, fmt.Errorf("updates require Linux/systemd") }
