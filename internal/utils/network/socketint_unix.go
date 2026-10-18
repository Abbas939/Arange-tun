//go:build !windows

package network

import "syscall"

func socketInt(fd uintptr, level, option, value int) error {
	return syscall.SetsockoptInt(int(fd), level, option, value)
}
func socketMSS(fd uintptr, value int) error {
	return socketInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, value)
}
