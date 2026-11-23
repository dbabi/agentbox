package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"agentbox/internal/image"
	"agentbox/internal/task"
)

// Each fixture is refused with the code the gate expects, so a VM FAIL is rootd's, not the fixture's.
func TestFixtures(t *testing.T) {
	fx, err := fixtures("arm64")
	if err != nil || len(fx) != len(want) {
		t.Fatalf("%d fixtures: %v", len(fx), err)
	}
	good, _ := image.Check(write(t, task.Archive("arm64")))
	for name, b := range fx {
		img, err := image.Check(write(t, b))
		var r *image.Refused
		got := ""
		if errors.As(err, &r) {
			got = r.Code
		} else if err != nil {
			t.Errorf("%s: untyped %v", name, err)
		}
		if got != want[name] {
			t.Errorf("%s: %q, want %q", name, got, want[name])
		}
		if name == "good" && img.ID != good.ID {
			t.Error("good is not the release's image")
		}
	}
}

func write(t *testing.T, b []byte) string {
	p := filepath.Join(t.TempDir(), "x.tar")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}
