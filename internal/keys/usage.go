package keys

import (
	"bytes"
	"encoding/json"
)

// usageOf reads what a reply says it used (§6.3 "Spend is reconciled from usage"), from a JSON reply or one SSE data
// line, for each vendor's shape. Anthropic counts input without the cache reads and writes; OpenAI's input includes
// its cached tokens, which come out into cacheRead here.
type usageJSON struct {
	InputTokens         int64 `json:"input_tokens"`
	OutputTokens        int64 `json:"output_tokens"`
	CacheReadInput      int64 `json:"cache_read_input_tokens"`
	CacheCreationInput  int64 `json:"cache_creation_input_tokens"`
	CacheCreationDetail *struct {
		M5 int64 `json:"ephemeral_5m_input_tokens"`
		H1 int64 `json:"ephemeral_1h_input_tokens"`
	} `json:"cache_creation"`
	InputDetails *struct {
		Cached int64 `json:"cached_tokens"`
	} `json:"input_tokens_details"`
	// Chat Completions
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	PromptDetails    *struct {
		Cached int64 `json:"cached_tokens"`
	} `json:"prompt_tokens_details"`
}

func (u usageJSON) usage(vendor string) usage {
	if vendor == "anthropic" {
		out := usage{in: u.InputTokens, out: u.OutputTokens, cacheRead: u.CacheReadInput, cacheWrite5m: u.CacheCreationInput, known: true}
		if d := u.CacheCreationDetail; d != nil && d.M5+d.H1 > 0 {
			out.cacheWrite5m, out.cacheWrite1h = d.M5, d.H1
		}
		return out
	}
	in, out, cached := u.InputTokens, u.OutputTokens, int64(0)
	if u.InputDetails != nil {
		cached = u.InputDetails.Cached
	}
	if u.PromptTokens+u.CompletionTokens > 0 {
		in, out = u.PromptTokens, u.CompletionTokens
		if u.PromptDetails != nil {
			cached = u.PromptDetails.Cached
		}
	}
	return usage{in: max(in-cached, 0), out: out, cacheRead: cached, known: true}
}

// merge keeps the larger count of each field: a stream reports usage more than once, and the later counts are totals.
func (u *usage) merge(v usage) {
	u.in, u.out = max(u.in, v.in), max(u.out, v.out)
	u.cacheRead, u.cacheWrite5m, u.cacheWrite1h = max(u.cacheRead, v.cacheRead), max(u.cacheWrite5m, v.cacheWrite5m), max(u.cacheWrite1h, v.cacheWrite1h)
	u.known = u.known || v.known
}

// fromJSON is the usage in one reply object or SSE event: the top-level usage member, or the one inside message
// (Anthropic's message_start) or response (OpenAI's response.completed).
func fromJSON(vendor string, b []byte) (usage, bool) {
	u, ok, _ := event(vendor, b)
	return u, ok
}

// event is fromJSON for one SSE event, and whether its usage is the request's final count: Anthropic's message_delta,
// which comes after the last content block (message_start's counts 1 output token); OpenAI's response.completed,
// .incomplete or .failed; a Chat Completions chunk, which carries usage only last.
func event(vendor string, b []byte) (usage, bool, bool) {
	var ev struct {
		Type     string                      `json:"type"`
		Object   string                      `json:"object"`
		Usage    *usageJSON                  `json:"usage"`
		Message  *struct{ Usage *usageJSON } `json:"message"`
		Response *struct{ Usage *usageJSON } `json:"response"`
	}
	if json.Unmarshal(b, &ev) != nil {
		return usage{}, false, false
	}
	for _, u := range []*usageJSON{ev.Usage, nested(ev.Message), nested(ev.Response)} {
		if u != nil {
			final := ev.Type == "message_delta"
			if vendor != "anthropic" {
				final = ev.Type == "response.completed" || ev.Type == "response.incomplete" || ev.Type == "response.failed" ||
					ev.Type == "" && ev.Object == "chat.completion.chunk"
			}
			return u.usage(vendor), true, final
		}
	}
	return usage{}, false, false
}

func nested(x *struct{ Usage *usageJSON }) *usageJSON {
	if x == nil {
		return nil
	}
	return x.Usage
}

// sseUsage collects usage from an SSE stream as it passes, a line at a time. final is set once the request's final
// count came: only then is u what the vendor bills.
type sseUsage struct {
	vendor string
	line   []byte
	u      usage
	final  bool
}

func (s *sseUsage) feed(b []byte) {
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			if len(s.line) < 1<<20 { // a data line past 1 MiB holds no usage worth its memory
				s.line = append(s.line, b...)
			}
			return
		}
		l := append(s.line, b[:i]...)
		s.line, b = s.line[:0], b[i+1:]
		if d, ok := bytes.CutPrefix(bytes.TrimRight(l, "\r"), []byte("data:")); ok {
			if u, ok, final := event(s.vendor, bytes.TrimSpace(d)); ok {
				s.u.merge(u)
				s.final = s.final || final
			}
		}
	}
}
