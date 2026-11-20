package nl

import (
	"encoding/binary"
	"testing"
)

func TestEncodeParse(t *testing.T) {
	payload := Attr(Attr(make([]byte, 12), rtaOIF, binary.NativeEndian.AppendUint32(nil, 3)), rtaGateway, []byte{10, 0, 2, 2})
	b := append(Encode(rtmNewRoute, 0, 1, payload), Encode(typeDone, 0, 1, nil)...)
	msgs, done, err := Parse(b)
	if err != nil || !done || len(msgs) != 1 || msgs[0].Type != rtmNewRoute {
		t.Fatalf("%v %v %v", msgs, done, err)
	}
	at, err := Attrs(msgs[0].Data[12:])
	if err != nil || binary.NativeEndian.Uint32(at[rtaOIF]) != 3 || len(at[rtaGateway]) != 4 {
		t.Fatalf("%v %v", at, err)
	}
	if _, _, err := Parse(b[:len(b)-20][:20]); err == nil {
		t.Fatal("a truncated message parsed")
	}
}

func TestRouteCheck(t *testing.T) {
	def := Route{Type: rtnUnicast, Table: tableMain, OIF: 2, Gateway: true, Prio: 100}
	other := Route{Type: rtnUnicast, Table: tableMain, OIF: 2, Gateway: true, Prio: 50}
	if d, ok := Default([]Route{def, {Type: rtnUnicast, DstLen: 24, Table: tableMain, OIF: 9}, other}); !ok || d != other {
		t.Fatalf("Default picked %+v", d)
	}
	for name, c := range map[string]struct {
		got  Route
		want string
	}{
		"public via the gateway": {Route{Type: rtnUnicast, OIF: 2, Gateway: true}, ""},
		"the box's own address":  {Route{Type: 2 /* RTN_LOCAL */, OIF: 1}, "route_not_unicast"},
		"on-link LAN address":    {Route{Type: rtnUnicast, OIF: 2}, "route_on_link"},
		"tailnet subnet route":   {Route{Type: rtnUnicast, OIF: 7, Gateway: true}, "route_not_default_interface"},
	} {
		if got := RouteCheck(c.got, def, true); got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
	}
	if RouteCheck(Route{Type: rtnUnicast}, Route{}, false) != NoDefaultRoute {
		t.Error("no default route")
	}
}
