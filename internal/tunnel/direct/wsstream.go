package direct

import (
	"github.com/gorilla/websocket"
	"io"
	"net"
	"sync"
	"time"
)

// wsStream keeps RFC 6455 framing (and client masking) after the upgrade, so
// HTTP proxies/CDNs can carry the stream. Readers and writers are serialized
// independently to satisfy gorilla's one-reader/one-writer contract.
type wsStream struct {
	c               *websocket.Conn
	readMu, writeMu sync.Mutex
	reader          io.Reader
}

func framedWebSocket(c *websocket.Conn) net.Conn { c.SetReadLimit(1 << 20); return &wsStream{c: c} }
func (w *wsStream) Read(p []byte) (int, error) {
	w.readMu.Lock()
	defer w.readMu.Unlock()
	for {
		if w.reader == nil {
			kind, r, err := w.c.NextReader()
			if err != nil {
				return 0, err
			}
			if kind != websocket.BinaryMessage {
				continue
			}
			w.reader = r
		}
		n, err := w.reader.Read(p)
		if err == io.EOF {
			w.reader = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}
func (w *wsStream) Write(p []byte) (int, error) {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()
	// Bound each frame without imposing a limit on a caller's stream write.
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 64<<10 {
			n = 64 << 10
		}
		if err := w.c.WriteMessage(websocket.BinaryMessage, p[:n]); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (w *wsStream) Close() error                       { return w.c.Close() }
func (w *wsStream) LocalAddr() net.Addr                { return w.c.LocalAddr() }
func (w *wsStream) RemoteAddr() net.Addr               { return w.c.RemoteAddr() }
func (w *wsStream) SetDeadline(t time.Time) error      { return w.c.NetConn().SetDeadline(t) }
func (w *wsStream) SetReadDeadline(t time.Time) error  { return w.c.NetConn().SetReadDeadline(t) }
func (w *wsStream) SetWriteDeadline(t time.Time) error { return w.c.NetConn().SetWriteDeadline(t) }
