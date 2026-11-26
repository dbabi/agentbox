package ops

import (
	"encoding/json"
	"regexp"
	"slices"
)

// The HTTP surfaces of a denial (§5.6 Surfaces): the proxy's CONNECT reply, keys' vendor error envelope and git's
// text/plain body. The in-task forwarders use them for BROKER_UNAVAILABLE; the brokers use the same functions.

// DenialHeaderName is the response header every broker denial carries; forwarders read only the response head.
const DenialHeaderName = "Agentbox-Denial"

// DenialHeader is the header value: `v1 code=<c> next=<n> id=<id>`.
func DenialHeader(d Denial) string {
	return "v1 code=" + d.Code + " next=" + string(d.Next) + " id=" + d.ID
}

var reHeader = regexp.MustCompile(`^v1 code=([A-Z][A-Z_]{1,40}) next=([a-z]{3,5}) id=((?:dn|pnd)_[0-7][0-9A-HJKMNP-TV-Z]{25})$`)

// ParseDenialHeader reads a DenialHeader value strictly: a code in the table, one of the six next moves, a denial or
// pending id.
func ParseDenialHeader(v string) (c Code, next Next, id string, ok bool) {
	m := reHeader.FindStringSubmatch(v)
	if m == nil {
		return Code{}, "", "", false
	}
	c, ok = LookupCode(m[1])
	next = Next(m[2])
	if !ok || !slices.Contains([]Next{Fix, Wait, Ask, Retry, Human, Stop}, next) {
		return Code{}, "", "", false
	}
	return c, next, m[3], true
}

// ConnectReason is the CONNECT reply's reason phrase, at most 64 bytes: curl and git show only the status line.
func ConnectReason(d Denial) string { return "agentbox " + d.Code + " (run: agentbox why)" }

// ConnectBody is the CONNECT reply's JSON body, {error, agentbox}.
func ConnectBody(d Denial) []byte {
	b, _ := json.Marshal(struct {
		Error    string `json:"error"`
		Agentbox Denial `json:"agentbox"`
	}{d.Msg, d})
	return b
}

// KeysBody is keys' error envelope: the vendor shape (error.type, error.message, which both Anthropic and OpenAI
// clients read) with the message starting `agentbox <CODE>:`, plus the agentbox member.
func KeysBody(d Denial) []byte { return KeysError(d, "api_error", "") }

// KeysError is KeysBody with the vendor's error type for its status and detail after msg: the vendor's own wording or
// a `capability_rejected:` token, which a CLI's retry matches (#18). The caller puts only grammar-checked request bytes
// in detail (a beta name, a field path).
func KeysError(d Denial, typ, detail string) []byte {
	type inner struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	}
	msg := "agentbox " + d.Code + ": " + d.Msg
	if detail != "" {
		msg += " " + detail
	}
	b, _ := json.Marshal(struct {
		Type     string `json:"type"`
		Error    inner  `json:"error"`
		Agentbox Denial `json:"agentbox"`
	}{"error", inner{typ, msg}, d})
	return b
}

// GitBody is git's text/plain body, and what pre-receive prints: msg after `agentbox <CODE>: `, as keys' message
// starts, then the denial JSON. git prints them as two remote: lines.
func GitBody(d Denial) []byte {
	return []byte("agentbox " + d.Code + ": " + d.Msg + "\n" + DenialPrefix + string(d.JSON()) + "\n")
}
