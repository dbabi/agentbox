package keys

import (
	"encoding/json"
	"strings"
	"testing"
)

// Requests shaped as the vendors document them (platform.claude.com/docs/en/api/messages, code.claude.com/docs/en/
// llm-gateway-protocol, OpenAI's Responses and Chat Completions references) pass; each refused shape gets its what,
// pointer and, where Claude Code's retry needs it, the vendor's wording.
func TestValidate(t *testing.T) {
	msgs := endpoints["/anthropic/v1/messages"]
	count := endpoints["/anthropic/v1/messages/count_tokens"]
	resp := endpoints["/openai/v1/responses"]
	chat := endpoints["/openai/v1/chat/completions"]
	cc := `{"model":"claude-opus-5-5","max_tokens":32000,"stream":true,"thinking":{"type":"adaptive"},"output_config":{"effort":"xhigh"},
		"metadata":{"user_id":"user_abc_session_1"},
		"system":[{"type":"text","text":"x-anthropic-billing-header: cc_version=2.1.330"},{"type":"text","text":"You are Claude Code.","cache_control":{"type":"ephemeral"}}],
		"tools":[{"name":"WebFetch","description":"fetch","input_schema":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}},
		         {"name":"Bash","input_schema":{"type":"object"},"cache_control":{"type":"ephemeral","ttl":"1h"}}],
		"messages":[{"role":"user","content":[{"type":"text","text":"<system-reminder>x</system-reminder>"},{"type":"text","text":"fix it","cache_control":{"type":"ephemeral"}}]},
		  {"role":"assistant","content":[{"type":"thinking","thinking":"","signature":"sig"},{"type":"tool_use","id":"toolu_1","name":"WebFetch","input":{"url":"https://example.com"}}]},
		  {"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":[{"type":"text","text":"page"}]},
		    {"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBO"}},
		    {"type":"document","source":{"type":"base64","media_type":"application/pdf","data":"JVBE"},"title":"a.pdf"}]},
		  {"role":"system","content":"a reminder"},
		  {"role":"system","content":[],"output_config":{"effort":"low"}}]}`
	for _, c := range []struct {
		name string
		ep   endpoint
		body string
	}{
		{"Claude Code turn", msgs, cc},
		{"count_tokens", count, `{"model":"claude-haiku-5-5","messages":[{"role":"user","content":"hi"}],"tools":[]}`},
		{"context editing", msgs, `{"model":"claude-sonnet-5-5","max_tokens":10,"messages":[],"context_management":{"edits":[{"type":"clear_tool_uses_20250919"}]}}`},
		{"Codex turn", resp, `{"model":"gpt-5.5","instructions":"be codex","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]},
			{"type":"reasoning","summary":[],"encrypted_content":"gAAA"},{"type":"function_call","call_id":"c1","name":"shell","arguments":"{\"command\":[\"ls\"]}"},
			{"type":"function_call_output","call_id":"c1","output":"a.go"},{"type":"custom_tool_call","call_id":"c2","name":"apply_patch","input":"*** Begin Patch"},
			{"type":"custom_tool_call_output","call_id":"c2","output":"ok"},{"role":"user","content":"easy message"}],
			"tools":[{"type":"function","name":"shell","description":"run","strict":false,"parameters":{"type":"object","properties":{"url":{}}}},
			{"type":"custom","name":"apply_patch","format":{"type":"grammar","syntax":"lark","definition":"start: x"}}],
			"tool_choice":"auto","parallel_tool_calls":false,"reasoning":{"effort":"medium","summary":"auto"},"store":false,"stream":true,
			"include":["reasoning.encrypted_content"],"prompt_cache_key":"019a","text":{"verbosity":"low"}}`},
		{"data: image in a chat request", chat, `{"model":"gpt-5.4-mini","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBO"}}]},
			{"role":"assistant","content":null,"tool_calls":[{"id":"t","type":"function","function":{"name":"f","arguments":"{\"url\":\"http://x\"}"}}]},
			{"role":"tool","tool_call_id":"t","content":"r"}],"tools":[{"type":"function","function":{"name":"f","parameters":{"type":"object"}}}],"n":1}`},
		{"Codex 0.171 (responses lite): its tools in an additional_tools item, by namespace; client_metadata; reasoning context", resp,
			`{"model":"gpt-6.2-sol","stream":true,"store":false,"tool_choice":"auto","parallel_tool_calls":true,"prompt_cache_key":"019a",
			"reasoning":{"effort":"low","context":"all_turns"},"text":{"verbosity":"low"},"include":["reasoning.encrypted_content"],
			"client_metadata":{"turn_id":"t1","x-codex-turn-metadata":"{\"session_id\":\"s\"}"},
			"input":[{"type":"additional_tools","id":"at_1","role":"developer","tools":[{"type":"namespace","name":"functions","description":"d",
			"tools":[{"type":"custom","name":"exec","description":"x","format":{"type":"grammar","syntax":"lark","definition":"start: x"}},
			{"type":"function","name":"wait","strict":false,"parameters":{"type":"object","properties":{"url":{"type":"string"}}}}]}]},
			{"type":"message","id":"msg_1","role":"developer","content":[{"type":"input_text","text":"You are Codex"}]},
			{"type":"function_call","call_id":"c1","name":"wait","namespace":"functions","arguments":"{}"}]}`},
		{"responses input_file with file_data", resp, `{"model":"gpt-5.5","input":[{"role":"user","content":[{"type":"input_file","file_data":"data:application/pdf;base64,JVBE","filename":"a.pdf"},
			{"type":"input_image","image_url":"data:image/png;base64,iVBO"}]}]}`},
	} {
		if _, r := validate(c.ep, []byte(c.body), nil); r != nil {
			t.Errorf("%s: refused: %+v", c.name, *r)
		}
	}
	for _, c := range []struct {
		name, body         string
		ep                 endpoint
		what, ptr, wording string
	}{
		{"URL image", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"url","url":"https://x/a.png"}}]}]}`,
			msgs, "url_field", "/messages/0/content/0/source/url", ""},
		{"URL PDF", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"url","url":"https://x/a.pdf"}}]}]}`,
			msgs, "url_field", "/messages/0/content/0/source/url", ""},
		{"a file source", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"file","file_id":"file_1"}}]}]}`,
			msgs, "url_field", "/messages/0/content/0/source/file_id", ""},
		{"a content source", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"content","content":"x"}}]}]}`,
			msgs, "source_type", "/messages/0/content/0/source/type", ""},
		{"mcp_servers", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[],"mcp_servers":[{"type":"url","url":"https://mcp.example","name":"m"}]}`,
			msgs, "field", "/mcp_servers", ""},
		{"container", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[],"container":"c1"}`, msgs, "field", "/container", ""},
		{"http image_url", `{"model":"gpt-5.4-mini","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"http://x/a.png"}}]}]}`,
			chat, "url_field", "/messages/0/content/0/image_url/url", ""},
		{"responses image by URL", `{"model":"gpt-5.5","input":[{"role":"user","content":[{"type":"input_image","image_url":"https://x/a.png"}]}]}`,
			resp, "url_field", "/input/0/content/0/image_url", ""},
		{"previous_response_id", `{"model":"gpt-5.5","input":"hi","previous_response_id":"resp_1"}`, resp, "field", "/previous_response_id", ""},
		{"background", `{"model":"gpt-5.5","input":"hi","background":true}`, resp, "field", "/background", ""},
		{"web_search with no policy", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[],"tools":[{"type":"web_search_20260209","name":"web_search"}]}`,
			msgs, "server_tool", "/tools/0/type", ""},
		{"an Anthropic-defined client tool", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[],"tools":[{"type":"bash_20250124","name":"bash"}]}`,
			msgs, "tool_type", "/tools/0/type", "tools.0.type: Input tag 'bash_20250124' found using 'type' does not match any of the expected tags"},
		{"openai web_search", `{"model":"gpt-5.5","input":"hi","tools":[{"type":"web_search"}]}`, resp, "server_tool", "/tools/0/type", ""},
		{"web_search in a Codex namespace", `{"model":"gpt-5.5","input":[{"type":"additional_tools","role":"developer","tools":[{"type":"namespace","name":"n","tools":[{"type":"web_search"}]}]}]}`,
			resp, "server_tool", "/input/0/tools/0/tools/0/type", ""},
		{"an image URL in a Codex tool output", `{"model":"gpt-5.5","input":[{"type":"function_call_output","call_id":"c","output":[{"type":"input_image","image_url":"https://x/a.png"}]}]}`,
			resp, "url_field", "/input/0/output/0/image_url", ""},
		{"a server tool result block", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[{"role":"user","content":[{"type":"web_search_tool_result","tool_use_id":"s","content":[]}]}]}`,
			msgs, "block_type", "/messages/0/content/0/type", "messages.0.content.0.type: Input tag 'web_search_tool_result' found using 'type' does not match any of the expected tags"},
		{"an item reference", `{"model":"gpt-5.5","input":[{"type":"item_reference","id":"msg_1"}]}`, resp, "block_type", "/input/0/type", ""},
		{"model", `{"model":"claude-2","max_tokens":1,"messages":[]}`, msgs, "model", "/model", ""},
		{"max_tokens", `{"model":"claude-haiku-4-5","max_tokens":64001,"messages":[]}`, msgs, "max_tokens", "/max_tokens", ""},
		{"an unknown field", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[],"safeguards":{"x":1}}`, msgs, "field", "/safeguards",
			"safeguards: Extra inputs are not permitted"},
		{"an unknown nested field", `{"model":"claude-opus-5-5","max_tokens":1,"messages":[],"output_config":{"effort":"high","speed":"fast"}}`, msgs, "field",
			"/output_config/speed", "output_config.speed: Extra inputs are not permitted"},
		{"a repeated key", `{"model":"claude-opus-5-5","model":"x","max_tokens":1,"messages":[]}`, msgs, "field", "/", ""},
		{"n above 1", `{"model":"gpt-5.4-mini","messages":[],"n":4}`, chat, "field", "/n", "n: only 1 is allowed"},
	} {
		_, r := validate(c.ep, []byte(c.body), nil)
		if r == nil {
			t.Errorf("%s: passed", c.name)
			continue
		}
		if r.what != c.what || r.ptr != c.ptr || (c.wording != "" && r.wording != c.wording) {
			t.Errorf("%s: %+v, want what %s ptr %s wording %q", c.name, *r, c.what, c.ptr, c.wording)
		}
	}
	// a server tool the policy allows passes, and is reported for its taint
	c, r := validate(msgs, []byte(`{"model":"claude-opus-5-5","max_tokens":1,"messages":[],"tools":[{"type":"web_search_20260209","name":"web_search","max_uses":3}]}`),
		func(f string) bool { return f == "web_search" })
	if r != nil || len(c.server) != 1 || c.server[0] != "web_search" {
		t.Errorf("allowed web_search: %v %+v", c.server, r)
	}
	// OpenAI's store goes out false, whatever the request said
	for _, b := range []string{`{"model":"gpt-5.5","input":"hi","store":true}`, `{"model":"gpt-5.5","input":"hi"}`} {
		c, r := validate(resp, []byte(b), nil)
		var out map[string]any
		if r != nil || json.Unmarshal(c.body, &out) != nil || out["store"] != false {
			t.Errorf("%s: forwarded %s (%+v)", b, c.body, r)
		}
	}
	// Anthropic's bytes go out as sent: preserved thinking and the attribution block need the request as Claude Code built it
	if c, _ := validate(msgs, []byte(cc), nil); string(c.body) != cc {
		t.Error("an Anthropic body was re-encoded")
	}
	if c, _ := validate(msgs, []byte(cc), nil); c.maxOut != 32000 || !c.stream || c.model != "claude-opus-5-5" {
		t.Errorf("checked %+v", c)
	}
}

func TestBetas(t *testing.T) {
	if r := checkBetas([]string{"claude-code-20250219,interleaved-thinking-2025-05-14", " context-1m-2025-08-07 "}, betas); r != nil {
		t.Errorf("allowed betas refused: %+v", *r)
	}
	r := checkBetas([]string{"claude-code-20250219", "mcp-client-2025-11-20"}, betas)
	if r == nil || r.what != "beta_header" || r.wording != "capability_rejected: beta_header:mcp-client-2025-11-20" {
		t.Errorf("mcp beta: %+v", r)
	}
	if r := checkBetas([]string{"oauth-2025-04-20"}, betas); r == nil || r.name != "oauth-2025-04-20" {
		t.Errorf("the OAuth beta (v1 is API keys only) passed: %+v", r)
	}
	if r := checkBetas([]string{"Bad Value\x1b[0m"}, betas); r == nil || r.wording != "" || r.name != "" {
		t.Errorf("a value outside the grammar was echoed: %+v", r)
	}
}

// FuzzValidate: no body panics the check, and nothing it passes holds a refused field or a URL-bearing key outside
// the client's own tool arguments and schemas.
func FuzzValidate(f *testing.F) {
	f.Add(`{"model":"claude-opus-5-5","max_tokens":1,"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","data":"x"}}]}]}`, 0)
	f.Add(`{"model":"gpt-5.5","input":[{"role":"user","content":[{"type":"input_image","image_url":"data:x"}]}],"tools":[{"type":"function","name":"f","parameters":{"url":1}}]}`, 2)
	f.Add(`{"model":"gpt-5.4-mini","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:,x"}}]}]}`, 3)
	eps := []endpoint{endpoints["/anthropic/v1/messages"], endpoints["/anthropic/v1/messages/count_tokens"], endpoints["/openai/v1/responses"],
		endpoints["/openai/v1/chat/completions"]}
	f.Fuzz(func(t *testing.T, body string, n int) {
		ep := eps[(n%len(eps)+len(eps))%len(eps)]
		c, r := validate(ep, []byte(body), func(string) bool { return true })
		if r != nil {
			return
		}
		v, err := decodeJSON(c.body)
		if err != nil {
			t.Fatalf("passed bytes that don't decode: %v", err)
		}
		top := v.(map[string]any)
		for _, k := range never {
			if _, ok := top[k]; ok {
				t.Fatalf("passed %s", k)
			}
		}
		if r := urlScan(top, nil); r != nil {
			t.Fatalf("passed a URL key at %s", r.ptr)
		}
		if strings.Contains(c.model, "\n") {
			t.Fatal("a model with a newline")
		}
	})
}
