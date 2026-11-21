package content

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const repo = "../../.." // site/tui/content -> repo root

func TestPages(t *testing.T) {
	pages, err := Pages()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"home", "install", "how", "security", "roadmap", "docs", "snib"}
	if len(pages) != len(want) {
		t.Fatalf("%d pages, want %d", len(pages), len(want))
	}
	for i, p := range pages {
		if p.Key != i+1 || p.Slug != want[i] {
			t.Fatalf("page %d: key %d slug %q, want %d %q", i, p.Key, p.Slug, i+1, want[i])
		}
		if len(p.Sources) == 0 {
			t.Fatalf("%s: no sources", p.Slug)
		}
		// each page lists its source docs, so drift can be reviewed
		for _, s := range p.Sources {
			if _, err := os.Stat(filepath.Join(repo, s)); err != nil {
				t.Errorf("%s: source %s: %v", p.Slug, s, err)
			}
		}
	}
}

// content/snib must stay byte-for-byte copies of the mascot files.
func TestSnibCopiesMatchMascot(t *testing.T) {
	src := map[string]string{
		"happy.json": "mascot/poses/happy.json", "thinking.json": "mascot/poses/thinking.json",
		"guarding.json": "mascot/poses/guarding.json", "sleeping.json": "mascot/poses/sleeping.json",
		"idle.json": "mascot/anim/idle.json", "grid32.json": "mascot/refine/r2/grid32.json",
		"grid32-ring.json": "mascot/refine/r2/grid32-ring.json",
	}
	for name, path := range src {
		a, err := FS.ReadFile("snib/" + name)
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join(repo, path))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("content/snib/%s differs from %s; copy it again", name, path)
		}
	}
}

func TestParse(t *testing.T) {
	p, err := Parse("---\nkey: 9\nslug: t\ntitle: t\npose: happy\nsources: a, b\n---\n" +
		"# see [docs](https://x/y) now [built]\n$ echo [built] [x](y)\n- a [b] c\n12. step\n> CAUTION: hot\n\n```\n  raw [ok]\n```\nplain [ok] text\n")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Sources, []string{"a", "b"}) {
		t.Fatalf("sources %q", p.Sources)
	}
	want := []Line{
		{Kind: Comment, Spans: []Span{{Text: "see "}, {Text: "docs", URL: "https://x/y"}, {Text: " now "}, {Text: "[built]", Tag: "built"}}},
		{Kind: Command, Spans: []Span{{Text: "echo [built] [x](y)"}}},
		{Kind: Bullet, Spans: []Span{{Text: "a [b] c"}}},
		{Kind: Step, N: 12, Spans: []Span{{Text: "step"}}},
		{Kind: Caution, Spans: []Span{{Text: "hot"}}},
		{Kind: Blank},
		{Kind: Pre, Raw: []string{"  raw [ok]"}},
		{Kind: Text, Spans: []Span{{Text: "plain "}, {Text: "[ok]", Tag: "ok"}, {Text: " text"}}},
	}
	if !reflect.DeepEqual(p.Lines, want) {
		t.Fatalf("got\n%#v\nwant\n%#v", p.Lines, want)
	}
	if got := p.Lines[0].Plain(); got != "see docs <https://x/y> now [built]" {
		t.Fatalf("Plain() = %q", got)
	}
	for _, bad := range []string{"no front matter", "---\nkey: 1\n", "---\nkey: 1\nslug: a\ntitle: a\npose: a\n---\n```\nopen"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q): want error", bad)
		}
	}
}

func TestPaletteSwatches(t *testing.T) {
	pages, _ := Pages()
	var n int
	for _, l := range pages[6].Lines {
		if l.Kind == Swatch {
			n++
		}
	}
	if n != 10 {
		t.Fatalf("%d swatches, want 10", n)
	}
}
