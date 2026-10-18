//go:build !linux

package direct

import "net"

func clampMSS(_ *net.TCPConn, _ int) {}
