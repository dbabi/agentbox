// Package secrets is the offline workspace credential scan (#104): a token an agent finds in a file can be used against
// any host its egress list allows, since the proxy doesn't strip credentials a task supplies itself. rootd runs Scan in
// a transient unit with no network (agentbox secretscan), before an agent's first task and at each egress grant, and
// blocks tasks on a hit until the file is fixed or the admin acknowledges it. It is a detection aid: a secret written
// after the scan, or encoded, is missed.
package secrets

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"path"
	"strings"

	"agentbox/internal/wsfs"
)

// Hit is one credential in a file. It never carries the credential.
type Hit struct {
	Path string `json:"path"`
	Rule string `json:"rule"`
	Line int    `json:"line"`
}

func (h Hit) String() string { return fmt.Sprintf("%s:%d (%s)", h.Path, h.Line, h.Rule) }

// Report is what `agentbox secretscan` prints: the network interfaces it saw (rootd refuses a report from a scan that
// could reach a network), how many files it read, and the hits. Truncated means the scan reached MaxHits and stopped:
// files after that were not read, so the list is not the whole set and can't be acknowledged.
type Report struct {
	Netdevs   []string `json:"netdevs"`
	Files     int      `json:"files"`
	Hits      []Hit    `json:"hits"`
	Truncated bool     `json:"truncated"`
}

// Limits: a file is scanned up to FileCap bytes, and a scan stops at MaxHits hits (the report is then Truncated).
const (
	FileCap = 16 << 20
	MaxHits = 1000
)

// Scan reads every regular file under root through wsfs (no link is followed, no FIFO blocks it) and returns the
// hits, in path order. Git's object store is skipped: it is compressed, so no rule matches there; a secret only in git
// history is missed. A file is matched against a rule only if it holds one of the rule's keywords.
func Scan(root string) (Report, error) {
	r := Report{Hits: []Hit{}}
	err := wsfs.Walk(root, func(e wsfs.Entry) error {
		if e.IsDir() && e.Name == "objects" && path.Base(path.Dir(e.Rel)) == ".git" {
			return fs.SkipDir
		}
		if !e.Mode.IsRegular() {
			return nil
		}
		if len(r.Hits) >= MaxHits {
			r.Truncated = true
			return fs.SkipAll
		}
		f, err := e.Open()
		if err != nil {
			return err
		}
		b, err := f.ReadAll(FileCap)
		f.Close()
		if err != nil && !errors.Is(err, wsfs.ErrTooLarge) {
			return err
		}
		if len(b) > FileCap { // shortcut: a secret past the first FileCap bytes of a file is missed
			b = b[:FileCap]
		}
		r.Files++
		r.Hits = append(r.Hits, Find(e.Rel, b)...)
		return nil
	})
	if err == fs.SkipAll { // wsfs.Walk passes it back: the walk stopped at MaxHits
		err = nil
	}
	if len(r.Hits) > MaxHits {
		r.Hits, r.Truncated = r.Hits[:MaxHits], true
	}
	return r, err
}

// Find returns the hits in one file's bytes, in rule order then offset order.
func Find(rel string, b []byte) []Hit {
	var out []Hit
	low := bytes.ToLower(b)
	for _, ru := range Rules {
		if !hasAny(low, ru.Keywords) {
			continue
		}
		for _, m := range ru.Re.FindAllSubmatchIndex(b, -1) {
			s, e := m[0], m[1]
			if len(m) >= 4 && m[2] >= 0 {
				s, e = m[2], m[3]
			}
			if entropy(b[s:e]) < ru.Entropy {
				continue
			}
			out = append(out, Hit{Path: rel, Rule: ru.ID, Line: 1 + bytes.Count(b[:s], []byte{'\n'})})
		}
	}
	return out
}

func hasAny(b []byte, kws []string) bool {
	for _, k := range kws {
		if bytes.Contains(b, []byte(k)) {
			return true
		}
	}
	return false
}

// entropy is the Shannon entropy of b in bits per byte, as gitleaks computes it.
func entropy(b []byte) float64 {
	var n [256]int
	for _, c := range b {
		n[c]++
	}
	h := 0.0
	for _, c := range n {
		if c > 0 {
			p := float64(c) / float64(len(b))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// Lookup returns the rule with id.
func Lookup(id string) (Rule, bool) {
	for _, r := range Rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// ForHost reports whether a credential of rule id works against host: the host is one of the rule's hosts, or under
// one. A rule with no hosts (a private key) matches none: it is named in the block, not at a grant.
func ForHost(id, host string) bool {
	r, ok := Lookup(id)
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range r.Hosts {
		if ok && (host == h || strings.HasSuffix(host, "."+h)) {
			return true
		}
	}
	return false
}
