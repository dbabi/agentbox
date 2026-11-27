package keys

// The model allowlist and its prices, a release constant (ARCHITECTURE.md §6.3): a model not here is refused with
// KEYS_REQUEST_REJECTED{model}. Prices are nanodollars per token, so $4 per million tokens is 4000; the "long" rates
// apply once a request's input passes longAbove tokens.
//
// Sources (opened 2026-11-26): Anthropic's list prices for current models, as the Claude API skill caches them on
// 2026-11-03 (Claude Haiku 5.5 bills $0.50/$2.50 above 100K prompt tokens); OpenAI's standard tier at
// developers.openai.com/api/docs/pricing (short context up to 272K input tokens, long above).
//
// shortcut: no prices.toml yet; a price change or a new model needs a release, which the closed allowlist wants anyway.
type price struct {
	in, out, cacheRead        int64
	longIn, longOut, longRead int64
	longAbove                 int64
	maxOut                    int64 // the max_tokens cap (§6.3), and what a request that names none reserves
}

// anthropicPrice is a Claude model: cache reads at a tenth of input; cache writes at 1.25x (5 min) or 2x (1 h), which
// spend computes from input.
func anthropicPrice(in, out, maxOut int64) price {
	return price{in: in, out: out, cacheRead: in / 10, longIn: in, longOut: out, longRead: in / 10, longAbove: 1 << 62, maxOut: maxOut}
}

func openaiPrice(in, cached, out, longIn, longCached, longOut int64) price {
	return price{in: in, out: out, cacheRead: cached, longIn: longIn, longOut: longOut, longRead: longCached, longAbove: 272_000, maxOut: 128_000}
}

func flat(p price) price {
	p.longIn, p.longOut, p.longRead, p.longAbove = p.in, p.out, p.cacheRead, 1<<62
	return p
}

var models = map[string]map[string]price{
	"anthropic": {
		"claude-fable-5-2":  anthropicPrice(8000, 40000, 128_000),
		"claude-mythos-5-2": anthropicPrice(8000, 40000, 128_000),
		"claude-fable-5-1":  anthropicPrice(10000, 50000, 128_000),
		"claude-mythos-5-1": anthropicPrice(10000, 50000, 128_000),
		"claude-fable-5":    anthropicPrice(10000, 50000, 128_000),
		"claude-opus-5-5":   anthropicPrice(4000, 20000, 128_000),
		"claude-opus-5":     anthropicPrice(5000, 25000, 128_000),
		"claude-opus-4-8":   anthropicPrice(5000, 25000, 128_000),
		"claude-opus-4-7":   anthropicPrice(5000, 25000, 128_000),
		"claude-opus-4-6":   anthropicPrice(5000, 25000, 128_000),
		"claude-sonnet-5-5": anthropicPrice(2000, 10000, 128_000),
		"claude-sonnet-5":   anthropicPrice(2000, 10000, 128_000),
		"claude-sonnet-4-6": anthropicPrice(3000, 15000, 128_000),
		"claude-haiku-5-5": func() price {
			p := anthropicPrice(100, 500, 128_000)
			p.longIn, p.longOut, p.longRead, p.longAbove = 500, 2500, 50, 100_000
			return p
		}(),
		"claude-haiku-4-5": anthropicPrice(1000, 5000, 64_000),
	},
	"openai": {
		"gpt-6.2-astra": openaiPrice(8000, 400, 40000, 16000, 800, 60000),
		"gpt-6.2-sol":   openaiPrice(2000, 100, 10000, 4000, 200, 15000),
		"gpt-6-astra":   openaiPrice(10000, 1000, 50000, 20000, 2000, 75000),
		"gpt-6.1-sol":   openaiPrice(2000, 100, 10000, 4000, 200, 15000),
		"gpt-6.1-terra": openaiPrice(1000, 50, 5000, 2000, 100, 7500),
		"gpt-6-luna":    openaiPrice(100, 10, 500, 200, 20, 750),
		"gpt-6-sol":     openaiPrice(2000, 200, 10000, 4000, 400, 15000),
		"gpt-5.6-sol":   openaiPrice(4000, 400, 20000, 8000, 800, 30000),
		"gpt-5.6-terra": openaiPrice(2000, 200, 12000, 4000, 400, 18000),
		"gpt-5.6-luna":  openaiPrice(200, 20, 1200, 400, 40, 1800),
		"gpt-5.5":       openaiPrice(5000, 500, 30000, 10000, 1000, 45000),
		"gpt-5.4":       openaiPrice(2500, 250, 15000, 5000, 500, 22500),
		"gpt-5.4-mini":  flat(openaiPrice(750, 75, 4500, 0, 0, 0)),
		"gpt-5.4-nano":  flat(openaiPrice(200, 20, 1250, 0, 0, 0)),
		"gpt-5.3-codex": flat(openaiPrice(1750, 175, 14000, 0, 0, 0)),
		"gpt-5.2":       flat(openaiPrice(1750, 175, 14000, 0, 0, 0)),
		"gpt-5.1":       flat(openaiPrice(1250, 125, 10000, 0, 0, 0)),
		"gpt-5":         flat(openaiPrice(1250, 125, 10000, 0, 0, 0)),
		"gpt-5-mini":    flat(openaiPrice(250, 25, 2000, 0, 0, 0)),
		"gpt-5-nano":    flat(openaiPrice(50, 5, 400, 0, 0, 0)),
	},
}

// usage is what a reply says it used, as each vendor reports it.
type usage struct {
	in, out, cacheRead, cacheWrite5m, cacheWrite1h int64
	known                                          bool // the reply carried usage
}

// cost is spend in nanodollars for p at u: Anthropic's input_tokens exclude cache reads and writes, OpenAI's
// input_tokens include its cached tokens (the caller subtracts them into cacheRead).
func (p price) cost(u usage) int64 {
	in, out, rd := p.in, p.out, p.cacheRead
	if u.in+u.cacheRead+u.cacheWrite5m+u.cacheWrite1h > p.longAbove {
		in, out, rd = p.longIn, p.longOut, p.longRead
	}
	return u.in*in + u.out*out + u.cacheRead*rd + u.cacheWrite5m*in*5/4 + u.cacheWrite1h*in*2
}

// reserve is §6.3's reservation: maxOut output tokens at the output price plus an input estimate (a token per 3 bytes
// of request body, at the long input rate when that passes longAbove).
func (p price) reserve(maxOut, bodyBytes int64) int64 {
	return p.cost(usage{in: bodyBytes / 3, out: maxOut})
}
