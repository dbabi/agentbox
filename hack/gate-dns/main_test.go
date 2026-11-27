package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func query(name string, qtype uint16, edns bool) []byte {
	q := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		q = append(append(q, byte(len(l))), l...)
	}
	q = append(q, 0)
	q = binary.BigEndian.AppendUint16(q, qtype)
	q = binary.BigEndian.AppendUint16(q, 1)
	if edns {
		q[11] = 1
		q = append(q, 0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0)
	}
	return q
}

func TestAnswer(t *testing.T) {
	recs := records{"pub.test": {netip.MustParseAddr("192.88.96.1"), netip.MustParseAddr("2600::1")}}
	r, ok := answer(query("pub.test", 1, true), "test", recs)
	if !ok || binary.BigEndian.Uint16(r[0:]) != 0x1234 || r[3]&0xf != 0 || binary.BigEndian.Uint16(r[6:]) != 1 || binary.BigEndian.Uint16(r[10:]) != 1 {
		t.Fatalf("A reply: %x", r)
	}
	if a := r[len(r)-11-4 : len(r)-11]; netip.AddrFrom4([4]byte(a)).String() != "192.88.96.1" {
		t.Errorf("A rdata %x", a)
	}
	if r, _ := answer(query("pub.test", 28, false), "test", recs); binary.BigEndian.Uint16(r[6:]) != 1 || binary.BigEndian.Uint16(r[10:]) != 0 {
		t.Errorf("AAAA reply: %x", r)
	}
	if r, _ := answer(query("bad.test", 1, false), "test", recs); r[3]&0xf != 3 {
		t.Errorf("unknown name: rcode %d, want NXDOMAIN", r[3]&0xf)
	}
	if _, ok := answer(query("pub.else", 1, false), "test", recs); ok {
		t.Error("a name outside the zone was answered")
	}
	recs["ipv4only.arpa"] = []netip.Addr{netip.MustParseAddr("2600:ffff:64::c000:aa")}
	if r, ok := answer(query("ipv4only.arpa", 28, false), "test", recs); !ok || binary.BigEndian.Uint16(r[6:]) != 1 {
		t.Errorf("a name given with -a outside the zone: %v %x", ok, r)
	}
}

// The hook answers resolved the way systemd 259's io.systemd.Resolve.Hook asks: a filter naming its names, wire-format
// records for them, and an empty reply (no rcode) that sends any other name on to DNS.
func TestHookReply(t *testing.T) {
	recs := records{"hook.gate.test": {netip.MustParseAddr("192.88.96.1"), netip.MustParseAddr("2600:ffff::1")}, "b.gate.test": nil}
	call := func(s string) map[string]any {
		b, _ := hookReply([]byte(s), recs)
		if len(b) == 0 || b[len(b)-1] != 0 {
			t.Fatalf("%s: reply %q is not one NUL-terminated message", s, b)
		}
		var m map[string]any
		if err := json.Unmarshal(b[:len(b)-1], &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := call(`{"method":"io.systemd.Resolve.Hook.QueryFilter","more":true}`)
	if d := m["parameters"].(map[string]any)["filterDomains"]; m["continues"] != true || len(d.([]any)) != 2 || d.([]any)[0] != "b.gate.test" {
		t.Fatalf("filter: %v", m)
	}
	if m := call(`{"method":"io.systemd.Resolve.Hook.QueryFilter"}`); m["continues"] != nil {
		t.Fatalf("a filter call without more got continues: %v", m)
	}
	m = call(`{"method":"io.systemd.Resolve.Hook.ResolveRecord","parameters":{"question":[{"key":{"class":1,"type":1,"name":"Hook.Gate.Test"}},{"key":{"class":1,"type":28,"name":"hook.gate.test"}}]}}`)
	p := m["parameters"].(map[string]any)
	ans, _ := p["answer"].([]any)
	if p["rcode"] != 0.0 || len(ans) != 2 {
		t.Fatalf("answer: %v", m)
	}
	name := []byte("\x04hook\x04gate\x04test\x00")
	for i, want := range [][]byte{{0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 88, 96, 1}, append([]byte{0, 28, 0, 1, 0, 0, 0, 30, 0, 16}, netip.MustParseAddr("2600:ffff::1").AsSlice()...)} {
		raw, err := base64.StdEncoding.DecodeString(ans[i].(map[string]any)["raw"].(string))
		if err != nil || !bytes.Equal(raw, append(slices.Clone(name), want...)) {
			t.Errorf("record %d: %x %v", i, raw, err)
		}
	}
	if m := call(`{"method":"io.systemd.Resolve.Hook.ResolveRecord","parameters":{"question":[{"key":{"class":1,"type":1,"name":"pub.gate.test"}}]}}`); len(m["parameters"].(map[string]any)) != 0 {
		t.Fatalf("another name must go on to DNS: %v", m)
	}
	if m := call(`{"method":"org.varlink.service.GetInfo"}`); m["error"] != "org.varlink.service.MethodNotFound" {
		t.Fatalf("unknown method: %v", m)
	}
	if b, _ := hookReply([]byte("{"), recs); b != nil {
		t.Fatalf("a broken message got %q", b)
	}
}
