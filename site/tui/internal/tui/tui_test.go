package tui

import (
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"

	"github.com/dbabi/agentbox/site/tui/content"
)

func press(s string) tea.KeyPressMsg {
	switch s {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	case "backspace":
		return tea.KeyPressMsg{Code: tea.KeyBackspace}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	}
	r := []rune(s)[0]
	return tea.KeyPressMsg{Code: r, Text: s}
}

func newModel(t *testing.T, w, h int, o Options) Model {
	t.Helper()
	if o.Profile == 0 {
		o.Profile = colorprofile.TrueColor
	}
	m, err := New(o)
	if err != nil {
		t.Fatal(err)
	}
	return send(m, tea.WindowSizeMsg{Width: w, Height: h})
}

func send(m Model, msgs ...tea.Msg) Model {
	for _, msg := range msgs {
		next, _ := m.Update(msg)
		m = next.(Model)
	}
	return m
}

func keys(m Model, ks ...string) Model {
	for _, k := range ks {
		m = send(m, press(k))
	}
	return m
}

func typed(m Model, s string) Model {
	for _, r := range s {
		m = send(m, press(string(r)))
	}
	return m
}

func TestKeyNames(t *testing.T) {
	for _, s := range []string{"j", "G", "?", "/", "enter", "esc", "tab"} {
		if got := press(s).String(); got != s {
			t.Errorf("press(%q).String() = %q", s, got)
		}
	}
}

func TestTabNavigation(t *testing.T) {
	m := newModel(t, 80, 24, Options{})
	for i, slug := range []string{"home", "install", "how", "security", "roadmap", "docs", "snib"} {
		if got := keys(m, string(rune('1'+i))).page().Slug; got != slug {
			t.Errorf("key %d: tab %s, want %s", i+1, got, slug)
		}
	}
	steps := []struct{ key, want string }{
		{"l", "install"}, {"]", "how"}, {"tab", "security"}, {"h", "how"}, {"[", "install"},
		{"[", "home"}, {"h", "snib"}, {"l", "home"},
	}
	for _, s := range steps {
		m = keys(m, s.key)
		if m.page().Slug != s.want {
			t.Fatalf("after %q: tab %s, want %s", s.key, m.page().Slug, s.want)
		}
	}
	if _, err := New(Options{Page: "nope"}); err == nil {
		t.Error("New(Page: nope) did not fail")
	}
	if got := newModel(t, 80, 24, Options{Page: "roadmap"}).page().Slug; got != "roadmap" {
		t.Errorf("start page %s, want roadmap", got)
	}
}

func TestPrompt(t *testing.T) {
	m := newModel(t, 80, 24, Options{})
	for _, c := range []struct{ line, want string }{
		{"cd roadmap", "roadmap"}, {"cat install", "install"}, {"security", "security"},
		{"cd ~/docs", "docs"}, {"snib", "snib"}, {"cd ~", "home"}, {"3", "how"},
	} {
		m = send(typed(keys(m, "/"), c.line), press("enter"))
		if m.page().Slug != c.want || m.prompting {
			t.Errorf("%q: tab %s prompting %v, want %s", c.line, m.page().Slug, m.prompting, c.want)
		}
	}
	m = send(typed(keys(m, ":"), "rm -rf"), press("enter"))
	if m.msg != "# command not found: rm -rf. try help" || !m.msgErr {
		t.Errorf("unknown command: msg %q err %v", m.msg, m.msgErr)
	}
	if !strings.Contains(ansi.Strip(m.View().Content), "# command not found: rm -rf. try help") {
		t.Error("error line not drawn above the prompt")
	}
	m = send(typed(keys(m, "/"), "help"), press("enter"))
	if !m.help {
		t.Error("help did not open the overlay")
	}
	if v := ansi.Strip(m.View().Content); !strings.Contains(v, "jump to a tab") || !strings.Contains(v, "copy go run") {
		t.Errorf("help overlay is missing keys:\n%s", v)
	}
	if m = keys(m, "esc"); m.help {
		t.Error("esc did not close help")
	}
	m = send(typed(keys(m, "/"), "ls"), press("enter"))
	if m.msg != "# home  install  how  security  roadmap  docs  snib" {
		t.Errorf("ls: %q", m.msg)
	}
	m = send(typed(keys(m, "/"), "x"), press("esc"))
	if m.prompting || len(m.input) != 0 {
		t.Error("esc did not leave and clear the prompt")
	}
}

func TestInputCaps(t *testing.T) {
	m := keys(newModel(t, 80, 24, Options{}), "/", "backspace") // backspace on empty does nothing
	m = typed(m, strings.Repeat("a", 70))
	if len(m.input) != maxInput {
		t.Errorf("typed 70, input has %d runes, want %d", len(m.input), maxInput)
	}
	m = keys(newModel(t, 80, 24, Options{}), "/")
	if m = send(m, tea.PasteMsg{Content: strings.Repeat("b", 65)}); len(m.input) != 0 {
		t.Errorf("a 65-byte paste was not dropped: %d runes", len(m.input))
	}
	if m = send(m, tea.PasteMsg{Content: "sec\x1b[31m"}); string(m.input) != "sec[31m" {
		t.Errorf("paste kept control bytes: %q", string(m.input))
	}
	m = keys(newModel(t, 80, 24, Options{}), "/")
	if m = keys(typed(m, "cd sec"), "tab"); string(m.input) != "cd security" {
		t.Errorf("tab completion: %q", string(m.input))
	}
	m = keys(newModel(t, 80, 24, Options{}))
	if m = send(m, tea.PasteMsg{Content: "q"}); m.page().Slug != "home" || len(m.input) != 0 {
		t.Error("a paste outside the prompt did something")
	}
}

func TestCursorAndCopy(t *testing.T) {
	m := newModel(t, 120, 40, Options{})
	start := m.cursor
	if m = keys(m, "j"); m.cursor != start+1 {
		t.Errorf("j: cursor %d, want %d", m.cursor, start+1)
	}
	if m = keys(m, "k", "k"); m.cursor != max(0, start-1) {
		t.Errorf("k: cursor %d", m.cursor)
	}
	rows := m.rows()
	if m = keys(m, "G"); m.cursor != len(rows)-1 {
		t.Errorf("G: cursor %d, want %d", m.cursor, len(rows)-1)
	}
	if m = keys(m, "g"); m.cursor != 0 || m.top != 0 {
		t.Errorf("g: cursor %d top %d", m.cursor, m.top)
	}
	for i, r := range rows {
		if r.cmd == MainCommand {
			m.cursor = i
		}
	}
	next, cmd := m.Update(press("enter"))
	if m = next.(Model); m.msg != "# copied" || cmd == nil {
		t.Errorf("enter on a $ line: msg %q, cmd %v", m.msg, cmd != nil)
	}
	m = send(m, clearMsg{m.msgSeq})
	if m.msg != "" {
		t.Error("the message did not clear")
	}
	m = keys(m, "6")
	for i, r := range m.rows() {
		if r.url != "" {
			m.cursor = i
			break
		}
	}
	if m = keys(m, "enter"); !strings.HasPrefix(m.msg, "# copied: https://github.com/dbabi/agentbox/blob/main/docs/") {
		t.Errorf("enter on a link: %q", m.msg)
	}
	if m = keys(m, "c"); m.msg != "# copied" {
		t.Errorf("c: %q", m.msg)
	}
}

func TestRenderSizes(t *testing.T) {
	for _, sz := range [][2]int{{80, 24}, {120, 40}, {40, 20}, {59, 30}} {
		w, h := sz[0], sz[1]
		for _, ascii := range []bool{false, true} {
			p := colorprofile.TrueColor
			if ascii {
				p = colorprofile.ASCII
			}
			m := newModel(t, w, h, Options{Profile: p})
			for i := range m.pages {
				m = keys(m, string(rune('1'+i)))
				v := m.View()
				if !v.AltScreen {
					t.Errorf("%dx%d: no alt screen", w, h)
				}
				lines := strings.Split(v.Content, "\n")
				if len(lines) != h {
					t.Errorf("%dx%d %s: %d lines", w, h, m.page().Slug, len(lines))
				}
				for n, l := range lines {
					if lw := ansi.StringWidth(l); lw > w {
						t.Errorf("%dx%d %s line %d is %d wide", w, h, m.page().Slug, n, lw)
					}
				}
				if !strings.Contains(ansi.Strip(lines[0]), m.page().Title+"]") {
					t.Errorf("%dx%d: active tab not in brackets: %q", w, h, ansi.Strip(lines[0]))
				}
				if !strings.Contains(ansi.Strip(lines[h-1]), "snib@agentbox:~/"+m.page().Slug+"$") {
					t.Errorf("%dx%d: no prompt: %q", w, h, ansi.Strip(lines[h-1]))
				}
				hasBlocks := strings.Contains(v.Content, "▀")
				wantArt := w >= 60 && h >= 24 || m.page().Pose == "all"
				if ascii && hasBlocks {
					t.Errorf("%dx%d %s: half blocks under the ASCII profile", w, h, m.page().Slug)
				}
				if !ascii && wantArt && m.page().Pose != "all" && !hasBlocks {
					t.Errorf("%dx%d %s: no Snib", w, h, m.page().Slug)
				}
				if !ascii && !wantArt && hasBlocks {
					t.Errorf("%dx%d %s: Snib shown below 60 cols", w, h, m.page().Slug)
				}
			}
		}
	}
	if !strings.Contains(newModel(t, 120, 40, Options{}).View().Content, "▣ agentbox") {
		t.Error("120x40: no brand")
	}
	if !strings.Contains(ansi.Strip(newModel(t, 140, 40, Options{}).View().Content), status) {
		t.Error("140x40: no status chip")
	}
	if v := newModel(t, 39, 11, Options{}).View().Content; v != "terminal too small: need 40x12" {
		t.Errorf("39x11: %q", v)
	}
}

func TestMotionAndIdle(t *testing.T) {
	m := newModel(t, 120, 40, Options{Motion: true, Page: "snib"})
	if m.Init() == nil {
		t.Fatal("no frame tick on the snib tab")
	}
	if m = send(m, frameMsg{}); m.frame != 1 {
		t.Errorf("frame %d after one tick", m.frame)
	}
	if m = keys(m, "m"); m.motion {
		t.Error("m did not pause")
	}
	if m = send(m, frameMsg{}); m.frame != 1 {
		t.Error("frame moved while paused")
	}
	if newModel(t, 80, 24, Options{SSH: true}).motion {
		t.Error("motion on by default over SSH")
	}

	s := newModel(t, 80, 24, Options{SSH: true})
	s = send(s, idleMsg{s.idleSeq})
	v := s.View()
	if !s.bye || v.AltScreen || !strings.Contains(v.Content, "# idle timeout, bye") {
		t.Errorf("idle: bye %v alt %v", s.bye, v.AltScreen)
	}
	if _, cmd := s.Update(quitMsg{s.idleSeq}); cmd == nil {
		t.Error("no quit after the goodbye")
	}
	s = keys(s, "j")
	if s.bye {
		t.Error("a key did not cancel the goodbye")
	}
	if _, cmd := s.Update(quitMsg{s.idleSeq - 1}); cmd != nil {
		t.Error("a stale idle timer quit the session")
	}
}

func TestWrapKeepsTags(t *testing.T) {
	for _, l := range wrap("- ", "  ", "aaaa bbbb cccc [partly built] dd", 18) {
		if strings.Contains(l, "[partly") != strings.Contains(l, "built]") {
			t.Errorf("tag split: %q", l)
		}
	}
	rows := lineRows(content.Line{Kind: content.Command, Spans: []content.Span{{Text: strings.Repeat("x", 100)}}}, 20)
	if len(rows) != 1 {
		t.Errorf("a command wrapped into %d rows", len(rows))
	}
}
