package attach

import (
	"slices"
	"testing"
	"time"
)

// #154: inotify sees a token version that lives far less than one poll interval.
func TestWatchSeesShortLivedToken(t *testing.T) {
	home := t.TempDir()
	creds(t, home, access)
	var s Seen
	stop, done := make(chan struct{}), make(chan struct{})
	go func() { s.Watch(home, time.Hour, stop); close(done) }()
	time.Sleep(100 * time.Millisecond)
	short := "gate-oauth-at-short-lived-FFFFFFFFFFFFFFF"
	creds(t, home, short)
	time.Sleep(100 * time.Millisecond)
	creds(t, home, "gate-oauth-at-final-GGGGGGGGGGGGGGGGGGGG")
	close(stop)
	<-done
	if !slices.Contains(s.All(), short) {
		t.Fatalf("seen %q", s.All())
	}
}
