package rootd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentbox/internal/ops"
	"agentbox/internal/rootd/resolve"
)

type stubSeal struct{}

func (stubSeal) Create(uint64) error       { return nil }
func (stubSeal) Seal(uint64, string) error { return nil }

type stubResolver struct{}

func (stubResolver) ResolveHostname(_ context.Context, name string) ([]netip.Addr, error) {
	if name == "ipv4only.arpa" {
		return []netip.Addr{netip.MustParseAddr("192.0.0.170")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("93.184.215.14")}, nil
}

type stubNft struct{}

func (stubNft) Run(string) error              { return nil }
func (stubNft) List(string) ([]string, error) { return nil, nil }

// FuzzRequest sends a short history of request lines (one per input line; sel[i] picks line i's socket) to the broker
// and seal sockets of a fresh rootd whose kernel, resolver and nft are stubs (issue #10). Each input gets its own
// rootd.db, so a crasher holds every line that built the state it needs and replays the same way under go test. The
// admin socket is left out: its refill runs the host's nft; its entries go through resolve.ParseEntry, which
// FuzzParseEntry covers, and its lines through the same decode.
func FuzzRequest(f *testing.F) {
	socks := []string{sockSeal, "resolve-keys", "resolve-git", "resolve-proxy", "resolve-ntfy"}
	seeds := []string{`{"op":"resolve","host":"api.example.com","port":443}`, `{"op":"resolve","host":"ntfy.sh","port":443,"task":"T1"}`,
		`{"call":"audit.seal","seg":1,"last_hash":"` + strings.Repeat("a", 64) + `"}`, `{"call":"audit.create","seg":1}`, `{"op":"resolve","x":1}`,
		`{"op":"resolve","host":"a.b","port":-1} trailing`}
	for _, l := range seeds {
		for i := range socks {
			f.Add([]byte{uint8(i)}, []byte(l))
		}
	}
	f.Add([]byte{1, 1, 0, 0}, []byte(strings.Join([]string{seeds[0], seeds[0], seeds[3], seeds[2]}, "\n")))
	log.SetOutput(io.Discard) // handle logs every refused seal call
	f.Fuzz(func(t *testing.T, sel, lines []byte) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "service.list"), []byte("keys api.example.com:443\ngit github.com:443\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		db, err := OpenDB(filepath.Join(dir, "rootd.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		s := &server{cfg: Config{EgressDir: dir}, db: db, seal: stubSeal{}, audit: func(map[string]any) error { return nil },
			svc: &resolve.Service{DB: db, Dir: dir, Resolver: stubResolver{}, Route: func(netip.Addr) string { return "" }, Nft: stubNft{},
				Flows: func(netip.Addr, uint16) (int, error) { return 0, nil }, Now: time.Now, Clock: func() (string, int64) { return "boot", 0 },
				Timeout: 10 * time.Minute}}
		for i, line := range bytes.SplitN(lines, []byte("\n"), 32) {
			sock := socks[0]
			if len(sel) > 0 {
				sock = socks[int(sel[i%len(sel)])%len(socks)]
			}
			out := s.line(sock, line)
			var rep map[string]any
			if len(out) == 0 || out[len(out)-1] != '\n' || strings.Count(string(out), "\n") != 1 || json.Unmarshal(out, &rep) != nil {
				t.Fatalf("line %d to %s: reply %q", i, sock, out)
			}
			if _, ok := rep["ok"].(bool); !ok {
				t.Fatalf("line %d to %s: reply %q has no ok", i, sock, out)
			}
		}
	})
}

// FuzzRootdDeny: whatever a broker sent and the resolver refused, rootd's DENY record passes auditd's sink check (C-G1).
func FuzzRootdDeny(f *testing.F) {
	svcs := []string{"keys", "git", "proxy"} // the brokers; deny drops rootd's own ntfy refresh
	f.Add(uint8(0), "evil.example:443", resolve.NotAllowlisted, "")
	f.Add(uint8(1), "192.168.1.10:80", resolve.NonPublic, "192.168.1.10: private4")
	f.Add(uint8(2), "bad name:x", "weird", strings.Repeat("é", 600))
	f.Add(uint8(3), "a.example:99999999999", resolve.Unavailable, "\x00\x1b[2J")
	t0 := time.Unix(1_800_000_000, 0)
	f.Fuzz(func(t *testing.T, si uint8, entry, code, detail string) {
		k := denyKey{svcs[int(si)%len(svcs)], code, entry}
		r := denyRecord(k, &denyWin{id: newDenyID(), n: 1, first: t0, last: t0, detail: detail})
		delete(r, "type")
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := ops.CheckDenyRecord("DENY", b); err != nil {
			t.Fatalf("%s: %v", b, err)
		}
	})
}
