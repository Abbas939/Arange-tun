//go:build nopcap

package packet

import (
	"context"
	"github.com/mahdi-byte64/arange-tun/config"
	"github.com/sirupsen/logrus"
)

func RunClient(_ context.Context, _ *config.PacketConfig, log *logrus.Logger) {
	log.Fatal("Packet is unavailable in a nopcap build; install the full CGO/libpcap build")
}
func RunServer(_ context.Context, _ *config.PacketConfig, log *logrus.Logger) {
	log.Fatal("Packet is unavailable in a nopcap build; install the full CGO/libpcap build")
}
