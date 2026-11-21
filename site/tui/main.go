// Command tui shows the agentbox site in a terminal. This first cut prints pages; the Bubble Tea app comes next.
//
//	go run github.com/dbabi/agentbox/site/tui@latest -plain security
//	go run . -art guarding
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/dbabi/agentbox/site/tui/content"
	"github.com/dbabi/agentbox/site/tui/internal/snib"
)

func main() {
	plain := flag.Bool("plain", false, "print the page as plain text, with no color or art (for screen readers and pipes)")
	page := flag.String("page", "home", "page to show: "+strings.Join(slugs(), ", "))
	art := flag.String("art", "", "print only Snib in this pose: happy, thinking, guarding, sleeping")
	flag.Parse()
	if flag.NArg() > 0 {
		*page = flag.Arg(0)
	}
	noColor := os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb"
	if *art != "" {
		out, err := drawSnib(*art, noColor)
		if err != nil {
			fail(err)
		}
		fmt.Print(out)
		return
	}
	p, err := find(*page)
	if err != nil {
		fail(err)
	}
	if !*plain {
		pose := p.Pose
		if pose == "all" {
			pose = "happy"
		}
		out, err := drawSnib(pose, noColor)
		if err != nil {
			fail(err)
		}
		fmt.Print(out)
	}
	fmt.Print(Plain(p, 76))
}

func drawSnib(pose string, noColor bool) (string, error) {
	g, err := snib.Load(pose)
	if err != nil {
		return "", err
	}
	if noColor {
		return snib.ASCII(g.Frames[0]), nil
	}
	return snib.HalfBlock(g.Palette, g.Frames[0]), nil
}

func slugs() []string {
	pages, _ := content.Pages()
	var s []string
	for _, p := range pages {
		s = append(s, p.Slug)
	}
	return s
}

func find(name string) (content.Page, error) {
	pages, err := content.Pages()
	if err != nil {
		return content.Page{}, err
	}
	for _, p := range pages {
		if p.Slug == name || fmt.Sprint(p.Key) == name {
			return p, nil
		}
	}
	return content.Page{}, fmt.Errorf("no such page: %s. try one of: %s", name, strings.Join(slugs(), ", "))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "agentbox-site:", err)
	os.Exit(1)
}

// Plain renders a page as linear text wrapped at width. Commands and Pre blocks are never wrapped.
func Plain(p content.Page, width int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# ~/%s\n\n", p.Slug)
	for _, l := range p.Lines {
		switch l.Kind {
		case content.Blank:
			b.WriteString("\n")
		case content.Command:
			b.WriteString("$ " + l.Plain() + "\n")
		case content.Pre:
			b.WriteString(strings.Join(l.Raw, "\n") + "\n")
		case content.Comment:
			wrap(&b, "# ", "# ", l.Plain(), width)
		case content.Bullet:
			wrap(&b, "- ", "  ", l.Plain(), width)
		case content.Step:
			pre := fmt.Sprintf("%d. ", l.N)
			wrap(&b, pre, strings.Repeat(" ", len(pre)), l.Plain(), width)
		case content.Caution:
			wrap(&b, "# CAUTION: ", "# ", l.Plain(), width)
		case content.Swatch:
			b.WriteString("  " + l.Plain() + "\n")
		default:
			wrap(&b, "", "", l.Plain(), width)
		}
	}
	return b.String()
}

func wrap(b *strings.Builder, first, rest, s string, width int) {
	line, pre := first, first
	for _, w := range strings.Fields(s) {
		if len(line) > len(pre) && len(line)+1+len(w) > width {
			b.WriteString(line + "\n")
			line, pre = rest, rest
		}
		if len(line) > len(pre) {
			line += " "
		}
		line += w
	}
	b.WriteString(line + "\n")
}
