package keys

import (
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The closed request schemas (ARCHITECTURE.md §6.3 Request validation): every object a request may hold, with the
// keys it may carry and what each value must be. A key outside them is refused; nothing in a request can make the
// vendor fetch anything. The shapes follow the vendors' own references (opened 2026-11-26):
// platform.claude.com/docs/en/api/messages and .../api/beta-headers, code.claude.com/docs/en/llm-gateway-protocol
// (what Claude Code sends a gateway: ?beta=true, HEAD /api/hello, role:"system" entries, adaptive thinking,
// output_config.effort, cache_control), and OpenAI's Responses and Chat Completions references, as Codex uses them.

// rej is one refusal: the KEYS_REQUEST_REJECTED what, the JSON pointer of the field, a closed-vocabulary name the
// reply may echo (a model, a block or tool type), the vendor's own wording for it (Claude Code's retry matches it,
// #18), and the max_tokens cap.
type rej struct {
	what, ptr, name, wording string
	limit                    int64
}

// path is a JSON pointer under construction.
type path []string

func (p path) key(k string) path { return append(slices.Clip(p), k) }
func (p path) idx(i int) path    { return append(slices.Clip(p), strconv.Itoa(i)) }
func (p path) ptr() string       { return "/" + strings.Join(p, "/") }

// dotted is the vendor's own way of naming a field in an error: output_config.effort, messages.3.content.0.
func (p path) dotted() string { return strings.Join(p, ".") }

// A spec checks one value at p.
type spec func(v any, p path) *rej

// obj is an object with exactly these keys allowed. An unknown key is the vendor's own 400 ("Extra inputs are not
// permitted"), which Claude Code reads as a capability its next request leaves out.
type obj map[string]spec

func (o obj) check(v any, p path) *rej {
	m, ok := v.(map[string]any)
	if !ok {
		return &rej{what: "field", ptr: p.ptr(), wording: p.dotted() + ": Input should be an object"}
	}
	for _, k := range sortedKeys(m) {
		s, ok := o[k]
		if !ok {
			return extra(p.key(k))
		}
		if s == nil {
			continue
		}
		if r := s(m[k], p.key(k)); r != nil {
			return r
		}
	}
	return nil
}

func (o obj) spec() spec { return o.check }

func extra(p path) *rej {
	return &rej{what: "field", ptr: p.ptr(), wording: p.dotted() + ": Extra inputs are not permitted"}
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// any value at all; the URL scan still runs over it unless it is opaque.
func anyv(any, path) *rej { return nil }

func str(v any, p path) *rej {
	if _, ok := v.(string); !ok {
		return &rej{what: "field", ptr: p.ptr(), wording: p.dotted() + ": Input should be a valid string"}
	}
	return nil
}

func boolean(v any, p path) *rej {
	if _, ok := v.(bool); !ok {
		return &rej{what: "field", ptr: p.ptr(), wording: p.dotted() + ": Input should be a valid boolean"}
	}
	return nil
}

func num(v any, p path) *rej {
	if _, ok := v.(json.Number); !ok {
		return &rej{what: "field", ptr: p.ptr(), wording: p.dotted() + ": Input should be a valid number"}
	}
	return nil
}

func oneOf(vals ...string) spec {
	return func(v any, p path) *rej {
		if s, ok := v.(string); !ok || !slices.Contains(vals, s) {
			return &rej{what: "field", ptr: p.ptr(), wording: p.dotted() + ": Input should be " + strings.Join(vals, ", ")}
		}
		return nil
	}
}

func list(each spec) spec {
	return func(v any, p path) *rej {
		a, ok := v.([]any)
		if !ok {
			return &rej{what: "field", ptr: p.ptr(), wording: p.dotted() + ": Input should be a valid list"}
		}
		for i, e := range a {
			if r := each(e, p.idx(i)); r != nil {
				return r
			}
		}
		return nil
	}
}

// strOr is a string, or else s.
func strOr(s spec) spec {
	return func(v any, p path) *rej {
		if _, ok := v.(string); ok {
			return nil
		}
		return s(v, p)
	}
}

// tagged is an object whose "type" picks its schema; a type not in the map is refused as what with the type echoed.
func tagged(what string, byType map[string]obj) spec {
	return func(v any, p path) *rej {
		m, ok := v.(map[string]any)
		if !ok {
			return &rej{what: "field", ptr: p.ptr(), wording: p.dotted() + ": Input should be an object"}
		}
		t, _ := m["type"].(string)
		o, ok := byType[t]
		if !ok {
			return typeRej(what, p, t)
		}
		return o.check(m, p)
	}
}

var reName = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

// typeRej refuses a block or tool type; only a name in the vendors' grammar is echoed.
func typeRej(what string, p path, t string) *rej {
	r := &rej{what: what, ptr: p.key("type").ptr()}
	if reName.MatchString(t) {
		r.name = t
		r.wording = p.dotted() + ".type: Input tag '" + t + "' found using 'type' does not match any of the expected tags"
	}
	return r
}

// The Anthropic Messages schema. cache_control and citations hold no URL a client can set to make the vendor fetch.
var (
	cacheControl = obj{"type": oneOf("ephemeral"), "ttl": oneOf("5m", "1h")}.spec()
	textBlock    = obj{"type": nil, "text": str, "cache_control": cacheControl, "citations": list(anyv)}
	// a source is inline bytes only (§6.3): base64 or text, never url, file or a container upload
	source = tagged("source_type", map[string]obj{
		"base64": {"type": nil, "media_type": str, "data": str},
		"text":   {"type": nil, "media_type": str, "data": str},
	})
	imageBlock = obj{"type": nil, "source": source, "cache_control": cacheControl}
	docBlock   = obj{"type": nil, "source": source, "cache_control": cacheControl, "title": str, "context": str,
		"citations": obj{"enabled": boolean}.spec()}
	resultContent = strOr(list(tagged("block_type", map[string]obj{"text": textBlock, "image": imageBlock, "document": docBlock})))
	blocks        = map[string]obj{
		"text": textBlock, "image": imageBlock, "document": docBlock,
		"tool_use":          {"type": nil, "id": str, "name": str, "input": nil, "cache_control": cacheControl},
		"tool_result":       {"type": nil, "tool_use_id": str, "content": resultContent, "is_error": boolean, "cache_control": cacheControl},
		"thinking":          {"type": nil, "thinking": str, "signature": str},
		"redacted_thinking": {"type": nil, "data": str},
	}
	content = strOr(list(tagged("block_type", blocks)))
	// a role:"system" entry mid-conversation (Claude Code sends them, code.claude.com/docs/en/llm-gateway-protocol):
	// text only, and an output_config with effort alone for the per-turn effort entry
	sysContent = strOr(list(tagged("block_type", map[string]obj{"text": textBlock})))
	effort     = oneOf("low", "medium", "high", "xhigh", "max")
	message    = func(v any, p path) *rej {
		m, _ := v.(map[string]any)
		switch m["role"] {
		case "user", "assistant":
			return obj{"role": nil, "content": content}.check(v, p)
		case "system":
			return obj{"role": nil, "content": sysContent, "output_config": obj{"effort": effort}.spec(), "cache_control": cacheControl}.check(v, p)
		}
		return &rej{what: "field", ptr: p.key("role").ptr(), wording: p.dotted() + ".role: Input should be 'user', 'assistant' or 'system'"}
	}
	toolChoice = obj{"type": oneOf("auto", "any", "tool", "none"), "name": str, "disable_parallel_tool_use": boolean}.spec()
	thinking   = obj{"type": oneOf("adaptive", "enabled", "disabled", "between_tools"), "budget_tokens": num,
		"display": oneOf("summarized", "omitted", "updates")}.spec()
	outputConfig = obj{"effort": effort, "format": obj{"type": oneOf("json_schema"), "schema": nil}.spec(),
		"task_budget": obj{"type": oneOf("tokens"), "total": num, "remaining": num}.spec()}.spec()
	// context editing clears old blocks on the vendor's side; it fetches nothing (beta context-management-2025-06-27)
	contextManagement = obj{"edits": list(tagged("field", map[string]obj{
		"clear_tool_uses_20250919": {"type": nil, "trigger": nil, "keep": nil, "clear_at_least": nil, "exclude_tools": list(str), "clear_tool_inputs": boolean},
		"clear_thinking_20251015":  {"type": nil, "keep": nil},
	}))}.spec()
	metadata = obj{"user_id": str}.spec()
	system   = strOr(list(tagged("block_type", map[string]obj{"text": textBlock})))
)

// never are request fields refused whatever their value (§6.3): each makes the vendor reach out, or keep state a
// later request could name. They get 403 like the other closed-list refusals, not the 400 of an unknown field.
var never = []string{"mcp_servers", "container", "previous_response_id", "conversation", "background", "prompt"}

// urlKeys are the URL-bearing keys refused at any depth (§6.3). Only an image_url, or the url inside one, that holds
// a data: URL passes; OpenAI's input_file passes only with file_data.
var urlKeys = []string{"url", "image_url", "file_url", "file_id"}

// opaque are the subtrees the URL scan skips: what the client's own tools take and return as arguments, and the JSON
// schemas it sends. A tool whose schema has a url property, or a tool_use whose input holds one, asks no vendor to
// fetch it: the client runs those tools itself, and their egress goes through the proxy.
func opaque(p path) bool {
	n := len(p)
	switch {
	case n == 3 && p[0] == "tools" && (p[2] == "input_schema" || p[2] == "parameters"),
		n == 4 && p[0] == "tools" && p[2] == "function" && p[3] == "parameters",
		n == 5 && p[0] == "messages" && p[2] == "content" && p[4] == "input", // a tool_use's arguments
		n == 3 && (p[0] == "output_config" || p[0] == "text") && p[1] == "format" && p[2] == "schema",
		n == 2 && p[0] == "response_format" && p[1] == "json_schema":
		return true
	}
	return false
}

// urlScan refuses a URL-bearing key anywhere outside the opaque subtrees.
func urlScan(v any, p path) *rej {
	if opaque(p) {
		return nil
	}
	switch x := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(x) {
			if slices.Contains(urlKeys, k) {
				if s, ok := x[k].(string); ok && (k == "url" || k == "image_url") && strings.HasPrefix(s, "data:") {
					continue
				}
				if _, ok := x[k].(map[string]any); ok && k == "image_url" {
					if r := urlScan(x[k], p.key(k)); r != nil {
						return r
					}
					continue
				}
				return &rej{what: "url_field", ptr: p.key(k).ptr()}
			}
			if r := urlScan(x[k], p.key(k)); r != nil {
				return r
			}
		}
	case []any:
		for i, e := range x {
			if r := urlScan(e, p.idx(i)); r != nil {
				return r
			}
		}
	}
	return nil
}

// serverFamily names the vendor-side tool a typed tool entry asks for, or "" when the type is not a server tool. A
// server tool passes only if the policy names its family, and then it taints the task (§6.3).
func serverFamily(t string) string {
	for _, f := range []string{"web_search", "web_fetch", "code_execution", "tool_search", "advisor", "mcp", "file_search",
		"code_interpreter", "image_generation", "computer_use"} {
		if t == f || strings.HasPrefix(t, f+"_") {
			return f
		}
	}
	return ""
}

// tools is a tools list: client tools by client's schema, and server tools the policy allows, collected in used.
func tools(client map[string]obj, allowed func(string) bool, used *[]string) spec {
	return list(func(v any, p path) *rej {
		m, ok := v.(map[string]any)
		if !ok {
			return &rej{what: "field", ptr: p.ptr(), wording: p.dotted() + ": Input should be an object"}
		}
		t, _ := m["type"].(string)
		if o, ok := client[t]; ok {
			return o.check(m, p)
		}
		if f := serverFamily(t); f != "" {
			if allowed == nil || !allowed(f) {
				r := typeRej("server_tool", p, t)
				r.wording = ""
				return r
			}
			if !slices.Contains(*used, f) {
				*used = append(*used, f)
			}
			return nil // its own config: the URL scan still ran over it
		}
		return typeRej("tool_type", p, t)
	})
}

var anthropicClientTool = obj{"type": nil, "name": str, "description": str, "input_schema": nil, "cache_control": cacheControl,
	"strict": boolean, "eager_input_streaming": boolean}

func anthropicBody(countTokens bool, allowed func(string) bool, used *[]string) obj {
	o := obj{"model": str, "messages": list(message), "system": system, "tools": tools(map[string]obj{"": anthropicClientTool,
		"custom": anthropicClientTool}, allowed, used), "tool_choice": toolChoice, "thinking": thinking, "output_config": outputConfig,
		"cache_control": cacheControl, "context_management": contextManagement}
	if !countTokens {
		for k, s := range map[string]spec{"max_tokens": num, "metadata": metadata, "stop_sequences": list(str), "stream": boolean,
			"temperature": num, "top_k": num, "top_p": num} {
			o[k] = s
		}
	}
	return o
}

// The OpenAI Responses schema, as Codex sends it with its agentbox model provider, and Chat Completions.
var (
	inputPart = map[string]obj{
		"input_text":  {"type": nil, "text": str},
		"output_text": {"type": nil, "text": str, "annotations": list(anyv), "logprobs": nil},
		"refusal":     {"type": nil, "refusal": str},
		"input_image": {"type": nil, "image_url": str, "detail": oneOf("low", "high", "auto")},
		"input_file":  {"type": nil, "file_data": str, "filename": str},
	}
	parts      = strOr(list(tagged("block_type", inputPart)))
	inputItems = map[string]obj{
		"message":                 {"type": nil, "id": str, "role": oneOf("user", "assistant", "system", "developer"), "content": parts, "status": str},
		"function_call":           {"type": nil, "id": str, "call_id": str, "name": str, "arguments": str, "status": str},
		"function_call_output":    {"type": nil, "id": str, "call_id": str, "output": parts, "status": str},
		"custom_tool_call":        {"type": nil, "id": str, "call_id": str, "name": str, "input": str, "status": str},
		"custom_tool_call_output": {"type": nil, "id": str, "call_id": str, "output": parts},
		"reasoning": {"type": nil, "id": str, "summary": list(obj{"type": oneOf("summary_text"), "text": str}.spec()),
			"content": list(obj{"type": oneOf("reasoning_text"), "text": str}.spec()), "encrypted_content": str, "status": str},
	}
	inputItem = func(v any, p path) *rej {
		if m, ok := v.(map[string]any); ok && m["type"] == nil && m["role"] != nil {
			return inputItems["message"].check(m, p) // an easy message: role and content, no type
		}
		return tagged("block_type", inputItems)(v, p)
	}
	openaiTool = obj{"type": nil, "name": str, "description": str, "parameters": nil, "strict": boolean}
	customTool = obj{"type": nil, "name": str, "description": str, "format": nil}
	textConfig = obj{"format": obj{"type": oneOf("text", "json_schema", "json_object"), "name": str, "schema": nil, "strict": boolean,
		"description": str}.spec(), "verbosity": oneOf("low", "medium", "high")}.spec()
	toolChoiceAny = func(v any, p path) *rej {
		if s, ok := v.(string); ok {
			return oneOf("auto", "none", "required")(s, p)
		}
		return obj{"type": oneOf("function", "custom", "allowed_tools"), "name": str, "mode": oneOf("auto", "required"), "tools": list(anyv)}.check(v, p)
	}
	reasoning = obj{"effort": oneOf("none", "minimal", "low", "medium", "high", "xhigh"), "summary": oneOf("auto", "concise", "detailed", "none"),
		"generate_summary": oneOf("auto", "concise", "detailed")}.spec()
	strMap = func(v any, p path) *rej {
		m, ok := v.(map[string]any)
		if !ok {
			return &rej{what: "field", ptr: p.ptr(), wording: p.dotted() + ": Input should be an object"}
		}
		for _, k := range sortedKeys(m) {
			if r := str(m[k], p.key(k)); r != nil {
				return r
			}
		}
		return nil
	}
	chatPart = map[string]obj{
		"text":      {"type": nil, "text": str},
		"image_url": {"type": nil, "image_url": obj{"url": str, "detail": oneOf("low", "high", "auto")}.spec()},
		"file":      {"type": nil, "file": obj{"file_data": str, "filename": str}.spec()},
		"refusal":   {"type": nil, "refusal": str},
	}
	chatMessage = obj{"role": oneOf("system", "developer", "user", "assistant", "tool"), "content": func(v any, p path) *rej {
		if v == nil {
			return nil // an assistant turn with tool_calls only
		}
		return strOr(list(tagged("block_type", chatPart)))(v, p)
	}, "name": str, "tool_call_id": str, "refusal": anyv, "tool_calls": list(obj{"id": str, "type": oneOf("function"),
		"function": obj{"name": str, "arguments": str}.spec()}.spec())}.spec()
	chatTool = obj{"type": nil, "function": obj{"name": str, "description": str, "parameters": nil, "strict": boolean}.spec()}
	one      = func(v any, p path) *rej {
		if n, ok := v.(json.Number); !ok || n.String() != "1" {
			return &rej{what: "field", ptr: p.ptr(), wording: p.dotted() + ": only 1 is allowed"}
		}
		return nil
	}
)

func responsesBody(allowed func(string) bool, used *[]string) obj {
	return obj{"model": str, "instructions": strOr(list(inputItem)), "input": strOr(list(inputItem)),
		"tools":       tools(map[string]obj{"function": openaiTool, "custom": customTool}, allowed, used),
		"tool_choice": toolChoiceAny, "parallel_tool_calls": boolean, "reasoning": reasoning, "store": boolean, "stream": boolean,
		"stream_options": obj{"include_obfuscation": boolean}.spec(), "include": list(oneOf("reasoning.encrypted_content", "message.output_text.logprobs")),
		"prompt_cache_key": str, "prompt_cache_retention": oneOf("in-memory", "24h"), "text": textConfig, "max_output_tokens": num,
		"max_tool_calls": num, "temperature": num, "top_p": num, "top_logprobs": num, "metadata": strMap, "truncation": oneOf("auto", "disabled"),
		"user": str, "safety_identifier": str, "service_tier": oneOf("auto", "default")}
}

func chatBody(allowed func(string) bool, used *[]string) obj {
	return obj{"model": str, "messages": list(chatMessage), "max_tokens": num, "max_completion_tokens": num, "temperature": num,
		"top_p": num, "stop": strOr(list(str)), "stream": boolean, "stream_options": obj{"include_usage": boolean, "include_obfuscation": boolean}.spec(),
		"tools": tools(map[string]obj{"function": chatTool}, allowed, used), "tool_choice": toolChoiceAny, "parallel_tool_calls": boolean,
		"response_format":  obj{"type": oneOf("text", "json_object", "json_schema"), "json_schema": nil}.spec(),
		"reasoning_effort": oneOf("none", "minimal", "low", "medium", "high", "xhigh"), "store": boolean, "user": str, "seed": num,
		"frequency_penalty": num, "presence_penalty": num, "logprobs": boolean, "top_logprobs": num, "n": one, "metadata": strMap,
		"service_tier": oneOf("auto", "default"), "prompt_cache_key": str, "safety_identifier": str, "verbosity": oneOf("low", "medium", "high")}
}

// endpoint is one route on a task's keys socket (§6.3 Endpoint allowlist): the in-task forwarder passes the CLIs'
// paths as they are, under /anthropic, /openai or /local (§4.3).
type endpoint struct {
	vendor, method, path string
	betaQuery            bool // ?beta=true allowed: Claude Code posts to /v1/messages?beta=true
	free                 bool // nothing to bill: the vendor doesn't charge for it
	countTokens          bool
}

var endpoints = map[string]endpoint{
	"/anthropic/v1/messages":              {vendor: "anthropic", method: "POST", path: "/v1/messages", betaQuery: true},
	"/anthropic/v1/messages/count_tokens": {vendor: "anthropic", method: "POST", path: "/v1/messages/count_tokens", betaQuery: true, free: true, countTokens: true},
	"/openai/v1/responses":                {vendor: "openai", method: "POST", path: "/v1/responses"},
	"/openai/v1/chat/completions":         {vendor: "openai", method: "POST", path: "/v1/chat/completions"},
	"/openai/v1/models":                   {vendor: "openai", method: "GET", path: "/v1/models", free: true},
	"/local/v1/chat/completions":          {vendor: "local", method: "POST", path: "/v1/chat/completions"},
}

// Hello is Claude Code's connection-warming probe (code.claude.com/docs/en/llm-gateway-protocol: "a HEAD /api/hello
// connection-warming probe ... it can reject without breaking anything"): keys answers it itself, with no upstream
// request, so it costs no denial in every task.
const Hello = "/anthropic/api/hello"

// betas are the anthropic-beta values keys forwards (§6.3): capabilities that make the vendor fetch nothing and keep
// no state a later request names. Claude Code runs with CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1 in tasks, so it
// sends only a few of these; on any other value keys answers the vendor's 400 with `capability_rejected:
// beta_header:<value>`, and Claude Code retries without it (#18). Not here on purpose: OAuth (v1 is API keys only),
// MCP, files, skills, code execution, the advisor, compaction, message threads, server-side fallbacks and fast mode,
// whose body fields keys refuses anyway.
var betas = []string{
	"claude-code-20250219", "interleaved-thinking-2025-05-14", "context-1m-2025-08-07", "effort-2025-11-24",
	"fine-grained-tool-streaming-2025-05-14", "token-efficient-tools-2025-02-19", "extended-cache-ttl-2025-04-11",
	"prompt-caching-2024-07-31", "token-counting-2024-11-01", "context-management-2025-06-27", "structured-outputs-2025-11-13",
	"task-budgets-2026-03-13", "mid-conversation-output-config-2026-07-01", "mid-conversation-system-clear-at-2026-08-21",
	"thinking-display-updates-2026-08-18", "cache-diagnosis-2026-04-07",
}

// openaiBetas are the OpenAI-Beta values keys forwards.
var openaiBetas = []string{"responses=experimental"}

var reBeta = regexp.MustCompile(`^[a-z0-9][a-z0-9=_.-]{0,63}$`)

// checkBetas refuses the first beta value outside allow, echoing it only in the vendor's grammar.
func checkBetas(vals []string, allow []string) *rej {
	for _, h := range vals {
		for _, b := range strings.Split(h, ",") {
			b = strings.TrimSpace(b)
			if b == "" || slices.Contains(allow, b) {
				continue
			}
			r := &rej{what: "beta_header"}
			if reBeta.MatchString(b) {
				r.name, r.wording = b, "capability_rejected: beta_header:"+b
			}
			return r
		}
	}
	return nil
}

// checked is a request that passed: what keys bills and forwards.
type checked struct {
	model  string
	maxOut int64    // the max output tokens the request may use: its own, or the model's cap
	stream bool     // the reply streams (SSE)
	server []string // the server-tool families it uses, which the policy allows and which taint the task
	body   []byte   // what goes upstream: the request's own bytes, except OpenAI's with store forced to false
	price  price
}

// validate is §6.3's check of one request body for ep. allowed says whether the policy names a server-tool family.
func validate(ep endpoint, body []byte, allowed func(string) bool) (checked, *rej) {
	c := checked{body: body}
	if ep.method == "GET" {
		if len(body) != 0 {
			return c, &rej{what: "field", ptr: "/", wording: "a GET request has no body"}
		}
		return c, nil
	}
	if !utf8Valid(body) {
		return c, &rej{what: "field", ptr: "/", wording: "the request body is not valid UTF-8"}
	}
	v, err := decodeJSON(body)
	if err != nil {
		return c, &rej{what: "field", ptr: "/", wording: "the request body is not one JSON object with unique keys"}
	}
	top, ok := v.(map[string]any)
	if !ok {
		return c, &rej{what: "field", ptr: "/", wording: "the request body must be a JSON object"}
	}
	for _, k := range never {
		if _, ok := top[k]; ok {
			return c, &rej{what: "field", ptr: path{k}.ptr()}
		}
	}
	if r := urlScan(top, nil); r != nil {
		return c, r
	}
	var schema obj
	switch {
	case ep.vendor == "anthropic":
		schema = anthropicBody(ep.countTokens, allowed, &c.server)
	case ep.path == "/v1/responses":
		schema = responsesBody(allowed, &c.server)
	default:
		schema = chatBody(allowed, &c.server)
	}
	if r := schema.check(top, nil); r != nil {
		return c, r
	}
	c.model, _ = top["model"].(string)
	p, ok := models[ep.vendor][c.model]
	if !ok {
		r := &rej{what: "model", ptr: "/model"}
		if reName.MatchString(c.model) {
			r.name = c.model
		}
		return c, r
	}
	c.price, c.maxOut = p, p.maxOut
	c.stream, _ = top["stream"].(bool)
	for _, k := range []string{"max_tokens", "max_output_tokens", "max_completion_tokens"} {
		n, ok := top[k].(json.Number)
		if !ok {
			continue
		}
		i, err := n.Int64()
		if err != nil || i < 0 || i > p.maxOut {
			return c, &rej{what: "max_tokens", ptr: path{k}.ptr(), limit: p.maxOut}
		}
		c.maxOut = i
	}
	if ep.vendor == "openai" && top["store"] != false {
		top["store"] = false // §6.3: nothing kept on the vendor's side for a later request to name
		c.body = encodeJSON(top)
	}
	return c, nil
}
