package audit

import (
	"bufio"
	"net"
	"path/filepath"
	"testing"
)

// Send returns nil only on an ACK: a NACK, a closed connection and a missing socket are errors.
func TestSend(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "p.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	replies := make(chan string, 3)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			bufio.NewReader(c).ReadBytes('\n')
			if r := <-replies; r != "" {
				c.Write([]byte(r + "\n"))
			}
			c.Close()
		}
	}()
	rec := map[string]any{"type": "TAINT", "subject": "task:t", "source": "cache:go"}
	replies <- `{"ok":true,"seq":7}`
	if err := Send(sock, rec); err != nil {
		t.Errorf("ACK: %v", err)
	}
	replies <- `{"ok":false,"code":"UNAVAILABLE"}`
	if err := Send(sock, rec); err == nil {
		t.Error("NACK: no error")
	}
	replies <- ""
	if err := Send(sock, rec); err == nil {
		t.Error("no reply: no error")
	}
	if err := Send(filepath.Join(t.TempDir(), "none.sock"), rec); err == nil {
		t.Error("no socket: no error")
	}
}
