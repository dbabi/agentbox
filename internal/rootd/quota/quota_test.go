package quota

import "testing"

func TestLimits(t *testing.T) {
	const G = 1 << 30
	for _, c := range []struct{ size, reserve, cas uint64 }{
		{35 * G, 4 * G, 35 * G / 10}, // 10% is 3.5 GiB: the 4 GiB floor wins
		{100 * G, 10 * G, 10 * G},
		{2000 * G, 200 * G, 200 * G},
	} {
		if r := Reserve(c.size); r != c.reserve || ParentLimit(c.size) != c.size-c.reserve || CASMax(c.size) != c.cas {
			t.Errorf("size %d: reserve %d limit %d cas %d", c.size, r, ParentLimit(c.size), CASMax(c.size))
		}
	}
	if ParentLimit(4*G) != 0 || ParentLimit(3*G) != 0 {
		t.Error("a file system no bigger than the reserve must get no 2/0 limit (Ensure refuses it)")
	}
}

// btrfs-progs 6.17.1 --format=json qgroup show -p -r -e, trimmed
const show = `{"__header": {"version": "1"}, "qgroup-show": [
 {"qgroupid": "0/5", "referenced": 16384, "max_referenced": "none", "exclusive": 16384, "max_exclusive": "none", "path": "", "parents": [], "children": []},
 {"qgroupid": "0/269", "referenced": 16384, "max_referenced": "none", "exclusive": 16384, "max_exclusive": 3757886668, "path": "@var_lib_agentbox/cas", "parents": ["2/0"], "children": []},
 {"qgroupid": "0/272", "referenced": 16384, "max_referenced": "none", "exclusive": 16384, "max_exclusive": "none", "path": "", "parents": ["1/999", "2/0"], "children": []},
 {"qgroupid": "2/0", "referenced": 114688, "max_referenced": 33283899392, "exclusive": 114688, "max_exclusive": "none", "path": "", "parents": [], "children": ["0/269"]}]}`

func TestParseShow(t *testing.T) {
	qs, err := parseShow([]byte(show))
	if err != nil {
		t.Fatal(err)
	}
	if q := qs["2/0"]; q.MaxRfer != 33283899392 || q.MaxExcl != 0 || len(q.Parents) != 0 {
		t.Errorf("2/0: %+v", q)
	}
	if q := qs["0/269"]; q.MaxExcl != 3757886668 || q.MaxRfer != 0 || !q.hasParent(Parent) {
		t.Errorf("0/269: %+v", q)
	}
	if !qs["0/272"].hasParent("2/0") || !qs["0/272"].hasParent("1/999") || qs["0/5"].hasParent(Parent) {
		t.Error("parents")
	}
	for _, bad := range []string{`{"qgroup-show": []}`, `{"qgroup-show": [{"qgroupid": "2/0", "max_referenced": "lots"}]}`, `not json`} {
		if _, err := parseShow([]byte(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

func TestParseMode(t *testing.T) {
	for s, want := range map[string]string{
		"Quotas on /var/lib/agentbox:\n  Enabled: no\n": "",
		"Quotas on /var/lib/agentbox:\n  Enabled:                 yes\n  Mode:                    qgroup (full accounting)\n  Inconsistent:            no\n": "qgroup",
		"Quotas on /x:\n  Enabled: yes\n  Mode: squota (simple accounting)\n":                                                                                "squota",
	} {
		if got, err := parseMode(s); err != nil || got != want {
			t.Errorf("parseMode(%q) = %q, %v; want %q", s, got, err, want)
		}
	}
	if _, err := parseMode("Quotas on /x:\n  Enabled: yes\n"); err == nil {
		t.Error("enabled with no mode accepted")
	}
}

func TestParseNested(t *testing.T) {
	out := "ID 260 gen 12 top level 259 path @var_lib_agentbox_data/workspaces/a/x\nID 261 gen 13 top level 259 path @var_lib_agentbox_data/workspaces/a/y z\n"
	if got := parseNested(out); len(got) != 2 || got[1] != "@var_lib_agentbox_data/workspaces/a/y z" {
		t.Errorf("parseNested: %q", got)
	}
	if got := parseNested(""); len(got) != 0 {
		t.Errorf("empty list: %q", got)
	}
}

func TestParseUUID(t *testing.T) {
	const s = "Label: none  uuid: 3f1c2a9e-5b7d-4e8a-9c0f-1a2b3c4d5e6f\n\tTotal devices 1 FS bytes used 2.10GiB\n"
	if u, err := parseUUID(s); err != nil || u != "3f1c2a9e-5b7d-4e8a-9c0f-1a2b3c4d5e6f" {
		t.Fatalf("got %q %v", u, err)
	}
	for _, bad := range []string{"", "Label: none  uuid: ../../x\n", "uuid:3f1c2a9e-5b7d-4e8a-9c0f-1a2b3c4d5e6f"} {
		if u, err := parseUUID(bad); err == nil {
			t.Errorf("%q: got %q", bad, u)
		}
	}
}
