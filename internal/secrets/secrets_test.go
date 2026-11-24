package secrets

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// tok builds a token of rule shape at run time, so no token-shaped literal sits in the repo.
func tok(prefix string, n int, alphabet string) string {
	r := rand.New(rand.NewPCG(1, uint64(len(prefix))))
	b := []byte(prefix)
	for range n {
		b = append(b, alphabet[r.IntN(len(alphabet))])
	}
	return string(b)
}

const alnum = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func TestFind(t *testing.T) {
	gh := tok("gh"+"p_", 36, alnum)
	aws := tok("AK"+"IA", 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	ant := tok("sk-ant-"+"api03-", 93, alnum+"_-") + "AA"
	body := "x = 1\nGH_TOKEN=" + gh + "\n\nkey: " + aws + "\nANTHROPIC_API_KEY=" + ant + "\n" +
		"low = gh" + "p_" + strings.Repeat("a", 36) + "\n" // one repeated letter: under the entropy floor
	got := Find("a/.env", []byte(body))
	want := []Hit{{"a/.env", "github-pat", 2}, {"a/.env", "aws-access-token", 4}, {"a/.env", "anthropic-api-key", 5}}
	if !slices.Equal(got, want) {
		t.Fatalf("Find = %v, want %v", got, want)
	}
	if strings.Contains(got[0].String(), gh) {
		t.Fatal("a hit carries the token")
	}
}

func TestForHost(t *testing.T) {
	for _, c := range []struct {
		rule, host string
		ok         bool
	}{{"github-pat", "github.com", true}, {"github-pat", "api.github.com", true}, {"github-pat", "evilgithub.com", false},
		{"github-pat", "GitHub.com.", true}, {"aws-access-token", "s3.us-east-1.amazonaws.com", true}, {"npm-access-token", "registry.npmjs.org", true},
		{"private-key", "github.com", false}, {"nope", "github.com", false}} {
		if ForHost(c.rule, c.host) != c.ok {
			t.Errorf("ForHost(%s, %s) != %v", c.rule, c.host, c.ok)
		}
	}
}

// Scan goes through wsfs: no link out of the tree, no FIFO, no git objects; a sparse file costs at most FileCap.
func TestScan(t *testing.T) {
	ws, out := t.TempDir(), t.TempDir()
	gh := tok("gh"+"o_", 36, alnum)
	os.WriteFile(filepath.Join(out, "outside"), []byte(gh), 0o600)
	os.MkdirAll(filepath.Join(ws, "src", ".git", "objects", "ab"), 0o755)
	os.WriteFile(filepath.Join(ws, "src", ".git", "config"), []byte("[remote \"o\"]\n\turl = https://x:"+gh+"@github.com/o/r\n"), 0o644)
	os.WriteFile(filepath.Join(ws, "src", ".git", "objects", "ab", "cd"), []byte(gh), 0o444)
	os.Symlink(filepath.Join(out, "outside"), filepath.Join(ws, "link"))
	syscall.Mkfifo(filepath.Join(ws, "fifo"), 0o644)
	f, _ := os.Create(filepath.Join(ws, "big"))
	f.Truncate(2 << 30)
	f.WriteAt([]byte(gh), 1<<30) // past FileCap: missed by design
	f.Close()
	r, err := Scan(ws)
	if err != nil || r.Files != 2 || !slices.Equal(r.Hits, []Hit{{"src/.git/config", "github-oauth", 2}}) {
		t.Fatalf("Scan = %+v, %v", r, err)
	}
}

func TestRulesCompileAndHaveKeywords(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if seen[r.ID] || len(r.Keywords) == 0 {
			t.Errorf("rule %s: duplicate or no keywords", r.ID)
		}
		seen[r.ID] = true
		for _, k := range r.Keywords {
			if k != strings.ToLower(k) {
				t.Errorf("rule %s: keyword %q is not lowercase", r.ID, k)
			}
		}
	}
}

// A scan that reaches MaxHits stops and says so: a credential in a file after the decoys is unread, so the report is
// marked truncated (rootd refuses to acknowledge it).
func TestScanTruncated(t *testing.T) {
	ws := t.TempDir()
	var b strings.Builder
	for range MaxHits {
		b.WriteString("token = " + tok("gh"+"p_", 36, alnum) + "\n")
	}
	os.WriteFile(filepath.Join(ws, "aaa-fixtures.txt"), []byte(b.String()), 0o644)
	os.WriteFile(filepath.Join(ws, "zzz.env"), []byte(tok("gh"+"o_", 36, alnum)), 0o644)
	r, err := Scan(ws)
	if err != nil || !r.Truncated || len(r.Hits) != MaxHits || r.Files != 1 {
		t.Fatalf("Scan = files %d, hits %d, truncated %v, %v", r.Files, len(r.Hits), r.Truncated, err)
	}
	os.Remove(filepath.Join(ws, "zzz.env"))
	if r, err := Scan(ws); err != nil || r.Truncated || len(r.Hits) != MaxHits {
		t.Fatalf("exactly MaxHits, nothing unread: truncated %v, hits %d, %v", r.Truncated, len(r.Hits), err)
	}
}
