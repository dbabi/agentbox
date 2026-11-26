package accounts

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentbox/internal/fw"

	_ "modernc.org/sqlite"
)

func openDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "rootd.db")+"?_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(Schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// §4.1: N only grows, so removing the newest agent and adding another never reuses its uid or sub-id range.
func TestNeverReused(t *testing.T) {
	db := openDB(t)
	now := time.Now()
	a, _ := Add(db, "a", now)
	b, _ := Add(db, "b", now)
	if a.N != 1 || b.N != 2 || b.UID() != 70002 || b.SubID() != 0x70020000 {
		t.Fatalf("a %+v b %+v", a, b)
	}
	if again, err := Add(db, "b", now); err != nil || again != b {
		t.Fatalf("re-adding an active agent: %+v %v", again, err)
	}
	if _, err := Retire(db, "b", now); err != nil {
		t.Fatal(err)
	}
	c, _ := Add(db, "c", now)
	b2, _ := Add(db, "b", now)
	if c.N != 3 || b2.N != 4 || c.UID() == b.UID() || c.SubID() == b.SubID() {
		t.Fatalf("after removing b: c %+v, b again %+v", c, b2)
	}
	if _, err := Retire(db, "b", now); err != nil {
		t.Fatal(err)
	}
	if _, err := Retire(db, "b", now); err != ErrNotFound {
		t.Fatalf("retiring twice: %v", err)
	}
	for _, q := range []string{`DELETE FROM ids WHERE n=2`, `UPDATE ids SET state='active' WHERE n=2`, `UPDATE ids SET n=9 WHERE n=1`,
		`UPDATE ids SET name='z' WHERE n=1`} {
		if _, err := db.Exec(q); err == nil {
			t.Errorf("%s: allowed", q)
		}
	}
	all, _ := List(db)
	if len(all) != 4 || all[1].Active || !all[2].Active || all[3].Active {
		t.Fatalf("rows: %+v", all)
	}
	sub, err := RenderSubids(nil, all)
	if err != nil || string(sub) != "ag-a:1879113728:65536\nag-c:1879244800:65536\n" {
		t.Fatalf("subids %q %v", sub, err)
	}
}

func TestFull(t *testing.T) {
	db := openDB(t)
	if _, err := db.Exec(`INSERT INTO ids(kind, n, name, state, created_at) VALUES('agent', 999, 'last', 'retired', 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := Add(db, "x", time.Now()); err != ErrFull {
		t.Fatalf("past N=999: %v", err)
	}
	for _, n := range []string{"", "A", "1a", "ag_x", strings.Repeat("a", 30), "a/b", "a\n"} {
		if ValidName(n) {
			t.Errorf("ValidName(%q)", n)
		}
	}
	if !ValidName(strings.Repeat("a", 29)) {
		t.Error("a 29-character name (32 with ag-) is valid")
	}
}

// Every uid and sub-id block lies in the static nft confined set (§4.1), so adding an agent never edits the firewall.
func TestInsideConfined(t *testing.T) {
	var lo, hi int
	fmt.Sscanf(fw.Confined[0], "%d-%d", &lo, &hi)
	var slo, shi int
	fmt.Sscanf(fw.Confined[2], "%d-%d", &slo, &shi)
	for _, n := range []int{1, MaxN} {
		a := Agent{N: n}
		if a.UID() < lo || a.UID() > hi || a.SubID() < slo || a.SubID()+SubSize-1 > shi || a.SubID()%SubSize != 0 {
			t.Errorf("N=%d: uid %d sub-ids %#x outside %v", n, a.UID(), a.SubID(), fw.Confined)
		}
	}
	if SubBase != slo || SubEnd != shi+1 {
		t.Errorf("sub-id span %#x-%#x, fw.Confined %v", SubBase, SubEnd, fw.Confined)
	}
}

func TestRenderSubids(t *testing.T) {
	cur := "# kept\nboxadmin:100000:65536\nag-old:1879113728:65536\n\n"
	got, err := RenderSubids([]byte(cur), []Agent{{N: 2, Name: "x", Active: true}})
	if err != nil || string(got) != "# kept\nboxadmin:100000:65536\nag-x:1879179264:65536\n" {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []string{"evil:1879048192:1\n", "evil:1879000000:100000\n", "evil:2013265919:1\n", "bad line\n", "x:1:y\n"} {
		if _, err := RenderSubids([]byte(bad), nil); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := RenderSubids([]byte("ok:2013265920:65536\nok2:1878982656:65536\n"), nil); err != nil {
		t.Errorf("entries just outside the span: %v", err)
	}
}

// #276: a stop that catches user@ in its ExecStartPre fails the unit, so the live teardown resets it after the stop.
func TestStopCmds(t *testing.T) {
	got := fmt.Sprint(Agent{N: 6, Name: "x"}.stopCmds())
	if want := "[[loginctl disable-linger ag-x] [loginctl terminate-user ag-x] [systemctl stop user@70006.service] " +
		"[systemctl reset-failed user@70006.service]]"; got != want {
		t.Errorf("teardown stops\n%s\nwant\n%s", got, want)
	}
}

func TestDropIns(t *testing.T) {
	a := Agent{N: 1, Name: "claude", Active: true}
	want := "Environment=XDG_CONFIG_HOME=/var/lib/agentbox/control/xdg/claude/config XDG_DATA_HOME=/var/lib/agentbox/control/xdg/claude/data\n"
	if d := a.UserDropIn(); !strings.Contains(d, want) || !strings.Contains(d, "ExecStartPre=+/var/lib/agentbox/current/bin/agentbox fwcheck\n") ||
		!strings.Contains(d, "\nEnvironment=CONTAINERS_STORAGE_CONF=/var/lib/agentbox/control/xdg/claude/config/containers/storage.conf\nUnsetEnvironment=CONTAINERS_STORAGE_CONF_OVERRIDE\n") ||
		a.userDropIn() != "/etc/systemd/system/user@70001.service.d/50-agentbox.conf" {
		t.Errorf("user@ drop-in:\n%s", d)
	}
	if c := a.StorageConf(); c != "[storage]\ndriver = \"overlay\"\ngraphroot = \"/var/lib/agentbox/data/agents/claude/storage\"\nrunroot = \"/run/user/70001/containers\"\n" {
		t.Errorf("storage.conf:\n%s", c)
	}
}
