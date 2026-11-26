package ops

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// The brokers' half of the §5.6 HTTP surfaces (§6.2, §6.3): the status a denial goes out with, the CONNECT refusal as
// bytes, keys' reply headers, what keys strips from an upstream reply, and the reply floors. The in-task forwarders
// use them for their own BROKER_UNAVAILABLE; the proxy, keys and git use the same functions.

// Status is the denial's HTTP status on the proxy, keys and git surfaces: the code's, except that a dial refused or
// blocked is 502 (§6.2 step 3) and an upstream timeout is 504 (§6.3).
func Status(d Denial) int {
	c, _ := LookupCode(d.Code)
	switch {
	case d.Code == "EGRESS_DIAL_FAILED" && d.What != "timeout":
		return http.StatusBadGateway
	case d.Code == "KEYS_UPSTREAM" && d.What == "timeout":
		return http.StatusGatewayTimeout
	}
	return HTTPStatus(c)
}

// ConnectReply is the proxy's whole CONNECT refusal: the status with the reason phrase `agentbox <CODE> (run: agentbox
// why)` (curl and git show only the status line), Agentbox-Denial, the {error, agentbox} JSON body, and
// Connection: close.
func ConnectReply(d Denial) []byte {
	body := ConnectBody(d)
	return fmt.Appendf(nil, "HTTP/1.1 %d %s\r\n%s: %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		Status(d), ConnectReason(d), DenialHeaderName, DenialHeader(d), len(body), body)
}

// KeysHeaders sets keys' denial headers (§5.6 Surfaces, §6.3): Agentbox-Denial, the JSON content type,
// x-should-retry (true only when next is retry, so a CLI stops within its own retry limits otherwise), and
// retry-after only for the caller's own day share, and only when it resets within the hour.
func KeysHeaders(h http.Header, d Denial, now time.Time) {
	h.Set(DenialHeaderName, DenialHeader(d))
	h.Set("Content-Type", "application/json")
	h.Set("x-should-retry", strconv.FormatBool(d.Next == Retry))
	if d.Code == "KEYS_BUDGET" && d.What == "agent" && d.ResetsAt != nil {
		if left := time.UnixMilli(*d.ResetsAt).Sub(now); left > 0 && left < time.Hour {
			h.Set("retry-after", strconv.FormatInt(int64((left+time.Second-1)/time.Second), 10))
		}
	}
}

// StripUpstream deletes every Agentbox-* header from an upstream reply (§6.3 Upstream responses): only the box sets
// them, and a forwarder logs what they say.
func StripUpstream(h http.Header) {
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "Agentbox-") {
			delete(h, k)
		}
	}
}

// StripMember drops the top-level agentbox member of a JSON object body (keys does it for every non-2xx upstream
// reply, §6.3), keeping the other members in order with their values as sent. A body with no such member, or that is
// not one JSON object, comes back unchanged.
func StripMember(b []byte) []byte {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return b
	}
	var out bytes.Buffer
	out.WriteByte('{')
	found := false
	for dec.More() {
		k, err := dec.Token()
		var v json.RawMessage
		if err != nil || dec.Decode(&v) != nil {
			return b
		}
		if k == "agentbox" {
			found = true
			continue
		}
		if out.Len() > 1 {
			out.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		out.Write(kb)
		out.WriteByte(':')
		out.Write(v)
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return b
	}
	if _, err := dec.Token(); err != io.EOF || !found {
		return b
	}
	out.WriteByte('}')
	return out.Bytes()
}

// Floor is a denial's reply floor (§5.6 leak rules 3 and 5): a missing item and another agent's leave at the same
// time, and so do every kind of ask.
func Floor(d Denial) time.Duration {
	switch d.Code {
	case "NOT_FOUND_OR_NOT_OWNED":
		return 200 * time.Millisecond
	case "NEEDS_SIGNATURE":
		return 2 * time.Second
	}
	return 0
}

// HoldFloor waits until receipt plus d's floor: call it just before the denial's first byte.
func HoldFloor(receipt time.Time, d Denial) { time.Sleep(time.Until(receipt.Add(Floor(d)))) }
