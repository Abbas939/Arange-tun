//go:build windows

package network

import "syscall"

func socketInt(fd uintptr, level, option, value int) error {
	return syscall.SetsockoptInt(syscall.Handle(fd), level, option, value)
}
func socketMSS(fd uintptr, value int) error { return nil } // MSS tuning is Linux-only.
