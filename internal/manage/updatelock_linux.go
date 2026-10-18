//go:build linux

package manage

import (
	"fmt"
	"github.com/mahdi-byte64/arange-tun/internal/app"
	"os"
	"syscall"
)

func lockUpdate() (func(), error) {
	if err := os.MkdirAll(app.ConfigDir, 0755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(app.ConfigDir+"/update.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another update is already running: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
