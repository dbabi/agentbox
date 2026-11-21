package rootd

import (
	"errors"
	"path/filepath"
	"testing"

	"agentbox/internal/rootd/resolve"
)

// §9: an allowlist edit is INTENT, ACK, effect, RESULT. With auditd down the INTENT gets no ACK and the list stays.
func TestEgressEditIsAudited(t *testing.T) {
	dir := t.TempDir()
	db, err := OpenDB(filepath.Join(dir, "rootd.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	e := resolve.Entry{Host: "evil.example", Port: 443}
	listed := func() bool {
		l, err := resolve.LoadLists(dir)
		return err == nil && l.AllowedAny("keys", e)
	}
	var recs []map[string]any
	down := true
	s := &server{cfg: Config{EgressDir: dir}, db: db, svc: &resolve.Service{DB: db, Dir: dir},
		audit: func(r map[string]any) error {
			if down {
				return errors.New("connect: no such file or directory")
			}
			r["listed"] = listed()
			recs = append(recs, r)
			return nil
		}}
	req := request{Op: "egress.allow", Svc: "keys", Entry: "evil.example:443"}
	if rep := s.admin(req); rep["ok"] != false || listed() {
		t.Fatalf("auditd down: %v, listed %v", rep, listed())
	}
	down = false
	s.admin(req) // the refill after it needs nft; the edit and its records are what count here
	if !listed() || len(recs) != 2 || recs[0]["type"] != "INTENT" || recs[0]["origin"] != "admin" || recs[0]["listed"] != false ||
		recs[1]["type"] != "RESULT" || recs[1]["opId"] != recs[0]["opId"] || recs[1]["status"] != "executed" || recs[1]["listed"] != true {
		t.Fatalf("records %v, listed %v", recs, listed())
	}
}
