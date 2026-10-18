//go:build linux

package direct

import (
	"net"
	"syscall"
)

func clampMSS(tcp *net.TCPConn, mss int) {
	if mss <= 0 {
		return
	}
	raw, err := tcp.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
	})
}
