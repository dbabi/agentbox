package ops

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"agentbox/internal/ids"
)

// The C-G1 and D-G2 fuzz targets. CI runs their seeds as tests; the 24 h run is `go test -fuzz` per target (issue #10).

// hostile are the C-G1 seed strings: ESC/CSI, U+009B, U+202E, U+2066-U+2069, U+0000, 64 KiB, URLs, base64 and
// secret-shaped values.
var hostile = []string{"\x1b[2J\x1b]0;x\x07", "\u009b31m", "\u202eevil", "\u2066\u2067\u2068\u2069", "a\x00b", strings.Repeat("A", 64<<10),
	"https://evil.example/x?y=1", "aGVsbG8gd29ybGQ=", "sk-ant-api03-" + strings.Repeat("x", 40), "ghp_" + strings.Repeat("Z", 36),
	"-----BEGIN OPENSSH PRIVATE KEY-----", "192.168.1.10", "example.com", "refs/heads/agent/a/x", strings.Repeat("a", 40), "\U000E0001"}

func FuzzDeny(f *testing.F) {
	for i, s := range hostile {
		f.Add(uint8(i), s, s, s, s, int64(i), s)
	}
	f.Add(uint8(10), "x.example", "origin", "refs/heads/agent/a/b", "/path", int64(443), "")
	f.Fuzz(func(t *testing.T, ci uint8, host, remote, ref, ptr string, n int64, free string) {
		c := genCodes[int(ci)%len(genCodes)]
		def := codeDefs[c.name]
		what := host
		if len(def.Whats) > 0 {
			what = def.Whats[int(n&0xff)%len(def.Whats)].Name
		}
		op := Registry[int(uint64(n)%uint64(len(Registry)))].Name
		build := func(free string) Denial {
			args := map[string]json.RawMessage{}
			for k, v := range map[string]any{"host": host, "port": n, "remote": remote, "ref": ref, "head": ref, "oid": host, "title": free,
				"body": free, "content": free, "reason": free, "value": free} {
				args[k], _ = json.Marshal(v)
			}
			sub := SubjectFrom(op, args)
			sub.Pointer, sub.Model, sub.Unit, sub.Package = ptr, remote, ref, host
			return Deny(c, what, Slots{Op: op, By: remote, Rule: ref, Subject: sub, Reason: free, Limit: &n, ResetsAt: &n, AsksLeft: &n,
				Pending: free, Open: []string{free, host}, ExpiresAt: &n, Expect: free})
		}
		d := build(free)
		b := d.JSON()
		if len(b) > MaxDenial || !printable(b) || len(d.Msg) > MaxMsg {
			t.Fatalf("shape: %d bytes %q", len(b), b)
		}
		if _, err := ParseDenial(b); err != nil {
			t.Fatalf("does not parse: %v %s", err, b)
		}
		// no byte of a free-text, hash- or drop-class input reaches the denial: changing it changes nothing but the id
		d2 := build(free + "Z")
		d2.ID = d.ID
		render(&d2, def, "")
		d1 := d
		render(&d1, def, "")
		if !bytes.Equal(d1.JSON(), d2.JSON()) {
			t.Fatalf("free text changed the denial:\n%s\n%s", d1.JSON(), d2.JSON())
		}
	})
}

func FuzzCheckDenial(f *testing.F) {
	for _, c := range genCodes {
		f.Add(Deny(c, "", Slots{Op: "repo.push", Pending: ids.New(ids.Pending)}).JSON())
	}
	for _, s := range hostile {
		f.Add([]byte(s))
	}
	req := []byte(`{"remote":"origin","ref":"refs/heads/agent/a/x","oid":"` + strings.Repeat("a", 40) + `"}`)
	f.Fuzz(func(t *testing.T, reply []byte) {
		d, w, ok := CheckDenial("repo.push", req, reply)
		b := d.JSON()
		if len(b) > MaxDenial || !printable(b) {
			t.Fatalf("shape %q", b)
		}
		if _, err := ParseWitness(w); err != nil {
			t.Fatalf("witness %q: %v", w, err)
		}
		if ok {
			if _, err := ParseDenial(b); err != nil {
				t.Fatal(err)
			}
		} else if d.Code != "BROKER_UNAVAILABLE" || !strings.HasSuffix(w, " malformed") {
			t.Fatalf("a failed reply shows %s", b)
		}
	})
}

func FuzzQuoteReply(f *testing.F) {
	f.Add([]byte(`{"items":[{"cost":"run","exact":true}],"asks":{"max":3,"used":1,"granted":0,"open":1,"openBatch":0,"left":2},"taint":{"tainted":false,"workspaceBound":false}}`), 1)
	for _, s := range hostile {
		f.Add([]byte(s), 2)
	}
	f.Fuzz(func(t *testing.T, b []byte, n int) {
		out, err := CheckQuoteReply(b, n)
		if err != nil {
			return
		}
		if !printable(out) {
			t.Fatalf("%q", out)
		}
		again, err := CheckQuoteReply(out, n)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("not a fixed point: %v", err)
		}
	})
}

func FuzzStatusReply(f *testing.F) {
	p := ids.New(ids.Pending)
	f.Add([]byte(`{"asks":{"max":3,"used":0,"granted":0,"open":1,"openBatch":0,"left":2},"taint":{"tainted":true,"workspaceBound":true},"open":["` + p +
		`"],"ask":{"id":"` + p + `","op":"repo.push","state":"executed","channel":"cli","expiresAt":5,"result":{"oid":"` + strings.Repeat("a", 40) + `"}}}`))
	for _, s := range hostile {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		out, err := CheckStatusReply(b)
		if err != nil {
			return
		}
		if !printable(out) || bytes.Contains(out, []byte("http")) {
			t.Fatalf("%q", out)
		}
		if again, err := CheckStatusReply(out); err != nil || !bytes.Equal(again, out) {
			t.Fatalf("not a fixed point: %v", err)
		}
	})
}

func FuzzBatchArgs(f *testing.F) {
	f.Add([]byte(`{"shape":"push+pr","ops":[{"name":"repo.push","args":{"remote":"o","ref":"refs/heads/agent/a/x","oid":"x"}},{"name":"gh.pr.create","args":{"remote":"o","head":"h","base":"main","title":"t","body":"b"}}]}`))
	for _, s := range hostile {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, op := range askOps {
			if d := CheckArgs(op, b); d != nil {
				if j := d.JSON(); len(j) > MaxDenial || !printable(j) || (d.Code != "INVALID_ARGS") {
					t.Fatalf("%s: %s", op, j)
				}
			}
		}
	})
}

func FuzzWitness(f *testing.F) {
	f.Add(WitnessLine(Deny(Busy, "", Slots{Op: "app.restart"})))
	f.Add("END " + strings.Repeat("0", 64))
	for _, s := range hostile {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		e, err := ParseWitness(line)
		if err != nil {
			return
		}
		if strings.ContainsAny(line, "\n\r\x00") || !printable([]byte(line)) {
			t.Fatalf("%q parsed as %+v", line, e)
		}
	})
}

func FuzzDenyRecord(f *testing.F) {
	f.Add([]byte(`{"id":"dn_01JF0000000000000000000000","code":"BUSY","by":"floor","count":1,"first":1,"last":1}`))
	f.Add([]byte(`{"id":"dn_01JF0000000000000000000000","code":"INVALID_ARGS","by":"gate","op":"file.write","args":{"content":{"sha256":"` + strings.Repeat("a", 64) + `","len":1}},"count":1,"first":1,"last":1}`))
	for _, s := range hostile {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if CheckDenyRecord("DENY", b) != nil {
			return
		}
		var r DenyRecord
		if err := exactDecode(b, &r); err != nil {
			t.Fatalf("accepted %s: %v", b, err)
		}
		if _, ok := codeDefs[r.Code]; !ok || len(r.Detail) > maxKeep {
			t.Fatalf("accepted %s", b)
		}
		for k, v := range r.Args {
			o, _ := opDef(r.Op)
			for _, fd := range o.Args {
				if fd.Name == k && fd.Audit == Hash && !bytes.HasPrefix(bytes.TrimSpace(v), []byte("{")) {
					t.Fatalf("unhashed %s accepted", k)
				}
			}
		}
	})
}
