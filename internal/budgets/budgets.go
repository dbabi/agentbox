// Package budgets is control/budgets.toml (ARCHITECTURE.md App. E): the box's caps, which the admin op budget.set
// replaces as a whole, and the per-agent LLM day shares rootd derives from it (§6.3). rootd, the proxy and keys read
// it. It takes a strict subset of TOML: one `key = <non-negative integer>` per line, `#` comments and blank lines,
// and only keys this release knows.
package budgets

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Paths on the box: the file budget.set writes, and the day shares rootd computes from it and the active agents.
const (
	Path       = "/var/lib/agentbox/control/budgets.toml"
	SharesPath = "/var/lib/agentbox/control/day-shares.json"
)

// Defaults are the keys this release knows and their values when the file doesn't set them. keys.day_cap_cents 0 is
// no box cap: until the admin sets one, keys checks only the trace budgets.
var Defaults = map[string]int64{
	"cache.agent_max_bytes":      8 << 30,
	"cache.task_fill_max_bytes":  2 << 30,
	"cache.task_fill_max_files":  20000,
	"cache.agent_fill_day_bytes": 4 << 30,
	"cache.max_idle_days":        30,
	"disk.reserve_bytes":         2 << 30,
	"keys.day_cap_cents":         0,
	// a task tree's spend (§6.3, §7): rootd registers each task's trace with keys, which reserves against it, so a
	// delegation fan-out has one cap; $20 until budget.set changes it
	"keys.trace_cents": 2000,
}

// SharePrefix keys an explicit day share: keys.agent_day_share.<agent>, in cents.
const SharePrefix = "keys.agent_day_share."

const maxValue = 1 << 62

var (
	reLine  = regexp.MustCompile(`^([a-z][a-z0-9_]*(?:\.[a-z0-9_-]+)+)[ \t]*=[ \t]*([0-9]{1,19})$`)
	reAgent = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
)

// Budgets are the values a file sets.
type Budgets map[string]int64

// Parse reads a budgets.toml. An unknown key, a repeated key, a negative or non-integer value, or any other TOML
// form is an error, so a typo never reads as a default.
func Parse(s string) (Budgets, error) {
	b := Budgets{}
	for i, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l[0] == '#' {
			continue
		}
		m := reLine.FindStringSubmatch(l)
		if m == nil {
			return nil, fmt.Errorf("budgets: line %d: not key = <integer>", i+1)
		}
		k := m[1]
		if _, ok := Defaults[k]; !ok && !(strings.HasPrefix(k, SharePrefix) && reAgent.MatchString(k[len(SharePrefix):])) {
			return nil, fmt.Errorf("budgets: line %d: unknown key %s", i+1, k)
		}
		v, err := strconv.ParseInt(m[2], 10, 64)
		if err != nil || v > maxValue {
			return nil, fmt.Errorf("budgets: line %d: %s is out of range", i+1, k)
		}
		if _, dup := b[k]; dup {
			return nil, fmt.Errorf("budgets: line %d: %s is set twice", i+1, k)
		}
		b[k] = v
	}
	if s, err := b.explicit(); err != nil {
		return nil, err
	} else if c := b.Get("keys.day_cap_cents"); len(s) > 0 && c == 0 {
		return nil, errors.New("budgets: day shares need keys.day_cap_cents")
	}
	return b, nil
}

// Read reads path; a missing file is no budgets set.
func Read(path string) (Budgets, error) {
	s, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Budgets{}, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(string(s))
}

// Get is key's value, or its default.
func (b Budgets) Get(key string) int64 {
	if v, ok := b[key]; ok {
		return v
	}
	return Defaults[key]
}

// Render is the file budget.set writes: every key set, sorted.
func (b Budgets) Render() string {
	keys := make([]string, 0, len(b))
	for k := range b {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var w strings.Builder
	w.WriteString("# Written by budget.set (ARCHITECTURE.md App. E); replace it with `agentbox budget set`.\n")
	for _, k := range keys {
		fmt.Fprintf(&w, "%s = %d\n", k, b[k])
	}
	return w.String()
}

// explicit are the explicit day shares; their sum, whatever agents exist, must not pass the box cap.
func (b Budgets) explicit() (map[string]int64, error) {
	s := map[string]int64{}
	var sum int64
	for k, v := range b {
		if a, ok := strings.CutPrefix(k, SharePrefix); ok {
			s[a] = v
			sum += v
		}
	}
	if c := b.Get("keys.day_cap_cents"); c > 0 && sum > c {
		return nil, fmt.Errorf("budgets: day shares sum to %d cents, above keys.day_cap_cents %d", sum, c)
	}
	return s, nil
}

// Shares are the per-agent LLM day shares (§6.3), in cents per UTC day. CapCents 0 means no box cap.
type Shares struct {
	CapCents int64            `json:"capCents"`
	Agents   map[string]int64 `json:"agents"`
}

// Shares splits the box day cap among the active agents: an explicit share where budget.set gave one, and the rest
// equally among the others. So one agent's spend never moves another's share; rootd recomputes them at agent.add,
// agent.remove and budget.set.
func (b Budgets) Shares(active []string) (Shares, error) {
	c := b.Get("keys.day_cap_cents")
	sh := Shares{CapCents: c, Agents: map[string]int64{}}
	if c == 0 {
		return sh, nil
	}
	ex, err := b.explicit()
	if err != nil {
		return Shares{}, err
	}
	rest, others := c, []string{}
	for _, a := range active {
		if v, ok := ex[a]; ok {
			sh.Agents[a] = v
			rest -= v
		} else {
			others = append(others, a)
		}
	}
	for _, a := range others {
		sh.Agents[a] = rest / int64(len(others))
	}
	return sh, nil
}

// Of is agent's day share; capped is false when the box has no cap. An agent with no share under a cap gets 0.
func (s Shares) Of(agent string) (cents int64, capped bool) {
	if s.CapCents == 0 {
		return 0, false
	}
	return s.Agents[agent], true
}

// ReadShares reads the shares rootd wrote; a missing file is no box cap.
func ReadShares(path string) (Shares, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Shares{}, nil
	}
	if err != nil {
		return Shares{}, err
	}
	var s Shares
	if err := json.Unmarshal(b, &s); err != nil {
		return Shares{}, fmt.Errorf("budgets: %s: %v", path, err)
	}
	return s, nil
}

// JSON is the shares file's content.
func (s Shares) JSON() []byte {
	b, _ := json.Marshal(s)
	return append(b, '\n')
}
