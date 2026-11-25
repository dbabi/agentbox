package witness

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"agentbox/internal/ids"
	"agentbox/internal/ops"
)

func writer(t *testing.T, root, task string) *os.File {
	t.Helper()
	fd, err := syscall.Open(filepath.Join(root, task, "witness"), syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	return os.NewFile(uintptr(fd), "witness")
}

func TestWitness(t *testing.T) {
	root := t.TempDir()
	w, err := Create(root, "task_1", -1)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(root, "task_1", "witness")); fi.Mode()&os.ModeNamedPipe == 0 || fi.Mode().Perm() != 0o620 {
		t.Fatalf("FIFO mode %v", fi.Mode())
	}
	if _, err := Create(root, "task_1", -1); err == nil {
		t.Fatal("a second Create of the same task")
	}
	if _, err := Create(root, "../x", -1); err == nil {
		t.Fatal("bad task id accepted")
	}
	d := ops.Deny(ops.BrokerUnavailable, "egress", ops.Slots{By: "forwarder"})
	good := ops.WitnessLine(d)
	end := "END " + strings.Repeat("a", 64)
	f := writer(t, root, "task_1")
	f.WriteString(good + "\n" + "junk line\n" + strings.Repeat("x", 1000) + "\n")
	// 1 MiB of well-formed lines: rootd keeps at most MaxKept bytes, counts the rest, and still keeps the last END
	junk := ops.WitnessLine(ops.Deny(ops.BrokerUnavailable, "llm", ops.Slots{By: "forwarder"})) + "\n"
	for n := 0; n < 1<<20; n += len(junk) {
		if _, err := f.WriteString(junk); err != nil {
			t.Fatal(err)
		}
	}
	f.WriteString(end + "\n")
	f.Close()
	r := w.Drain()
	kept := 0
	for _, l := range r.Lines {
		kept += len(l) + 1
	}
	if r.Lines[0] != good || r.Bad != 2 || r.Dropped == 0 || kept > MaxKept || r.End != strings.Repeat("a", 64) || r.Incomplete {
		t.Fatalf("lines %d (%d bytes), first %q, bad %d, dropped %d, end %q", len(r.Lines), kept, r.Lines[0], r.Bad, r.Dropped, r.End)
	}
	if err := w.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "task_1")); !os.IsNotExist(err) {
		t.Fatal("Remove left the dir")
	}
}

func TestReopen(t *testing.T) {
	root := t.TempDir()
	w, err := Create(root, "task_2", -1)
	if err != nil {
		t.Fatal(err)
	}
	w.f.Close() // rootd stopped: nothing reads the FIFO
	<-w.done
	// a writer that finds no reader is refused at open, so nothing queues while rootd is down
	if _, err := os.OpenFile(filepath.Join(root, "task_2", "witness"), os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
		t.Fatal("open with no reader succeeded")
	}
	w2, err := Reopen(root, "task_2")
	if err != nil {
		t.Fatal(err)
	}
	f := writer(t, root, "task_2")
	f.WriteString(ids.New(ids.Denial) + " - BROKER_UNAVAILABLE forwarder\n")
	f.Close()
	if r := w2.Drain(); !r.Incomplete || len(r.Lines) != 1 {
		t.Fatalf("%+v", r)
	}
	w2.Remove()
}

// #222 R55: END lines after the first and bytes with no newline count against MaxKept, so a flood of either shows in
// Dropped; the last END is still kept.
func TestWitnessFloodCounted(t *testing.T) {
	end := "END " + strings.Repeat("a", 64) + "\n"
	for name, flood := range map[string]string{"END lines": strings.Repeat(end, 2*MaxKept/len(end)), "no newline": strings.Repeat("x", 2*MaxKept)} {
		root := t.TempDir()
		w, err := Create(root, "task_3", -1)
		if err != nil {
			t.Fatal(err)
		}
		f := writer(t, root, "task_3")
		if _, err := f.WriteString(flood); err != nil {
			t.Fatal(err)
		}
		f.Close()
		r := w.Drain()
		w.Remove()
		if r.Dropped == 0 || name == "END lines" && r.End != strings.Repeat("a", 64) {
			t.Errorf("%s: %+v", name, r)
		}
	}
}
