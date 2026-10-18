package socksproxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestCancellationStopsAcceptLoop(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Serve(ctx, ln, nil, nil); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("accept loop survived cancellation")
	}
}
func TestRejectsUnsupportedAuthentication(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	go handle(context.Background(), b, func(context.Context, string, string) (net.Conn, error) {
		t.Error("dialed before authentication negotiation")
		return nil, nil
	}, nil)
	if _, err := a.Write([]byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(a, reply[:]); err != nil {
		t.Fatal(err)
	}
	if reply != [2]byte{5, 255} {
		t.Fatalf("reply %v", reply)
	}
}
