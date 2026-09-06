package addr

import (
	"testing"
)

func TestParseIPSpecSingle(t *testing.T) {
	rs, err := ParseIPSpec("1.2.3.4", true)
	if err != nil {
		t.Fatalf("ParseIPSpec: %v", err)
	}
	if len(rs) != 1 || rs[0].Count() != 1 {
		t.Fatalf("unexpected ranges: %+v", rs)
	}
	if got := Uint32ToIP(rs[0].Start).String(); got != "1.2.3.4" {
		t.Fatalf("got %s", got)
	}
}

func TestParseIPSpecCIDRTrimsEdges(t *testing.T) {
	rs, err := ParseIPSpec("192.168.1.0/30", true)
	if err != nil {
		t.Fatalf("ParseIPSpec: %v", err)
	}
	if len(rs) != 1 || rs[0].Count() != 2 {
		t.Fatalf("/30 应保留 2 个主机地址，got %+v", rs)
	}
	if got := Uint32ToIP(rs[0].Start).String(); got != "192.168.1.1" {
		t.Fatalf("got %s", got)
	}
	if got := Uint32ToIP(rs[0].End).String(); got != "192.168.1.2" {
		t.Fatalf("got %s", got)
	}
}

func TestParseIPSpecRangeAutoSwap(t *testing.T) {
	rs, err := ParseIPSpec("1.2.3.10-1.2.3.1", true)
	if err != nil {
		t.Fatalf("ParseIPSpec: %v", err)
	}
	if len(rs) != 1 || rs[0].Count() != 10 {
		t.Fatalf("区间应自动交换并包含 10 个地址，got %+v", rs)
	}
}

func TestParseIPSpecRejectsIPv6(t *testing.T) {
	if _, err := ParseIPSpec("::1", true); err == nil {
		t.Fatal("IPv6 应被拒绝")
	}
}

func TestParsePortsMixed(t *testing.T) {
	ps, err := ParsePorts("1080,8080,1024-1026,1080")
	if err != nil {
		t.Fatalf("ParsePorts: %v", err)
	}
	want := []uint16{1080, 8080, 1024, 1025, 1026}
	if len(ps) != len(want) {
		t.Fatalf("got %v", ps)
	}
	for i := range want {
		if ps[i] != want[i] {
			t.Fatalf("got %v, want %v", ps, want)
		}
	}
}

// 中文逗号不应导致整个端口表达式被当成非法端口（回归测试）。
func TestParsePortsChineseComma(t *testing.T) {
	ps, err := ParsePorts("1080，8080")
	if err != nil {
		t.Fatalf("ParsePorts: %v", err)
	}
	if len(ps) != 2 || ps[0] != 1080 || ps[1] != 8080 {
		t.Fatalf("got %v", ps)
	}
}

func TestParsePortsRejectsOutOfRange(t *testing.T) {
	for _, spec := range []string{"0", "65536", "80-70000"} {
		if _, err := ParsePorts(spec); err == nil {
			t.Fatalf("%q 应被拒绝", spec)
		}
	}
}

func TestIsReserved(t *testing.T) {
	cases := map[string]bool{
		"10.0.0.1":      true,
		"172.16.0.1":    true,
		"192.168.1.1":   true,
		"127.0.0.1":     true,
		"224.0.0.1":     true,
		"8.8.8.8":       false,
		"47.100.10.20":  false,
		"203.0.113.1":   true, // TEST-NET-3
		"198.51.100.1":  true, // TEST-NET-2
		"192.0.2.1":     true, // TEST-NET-1
		"100.64.0.1":    true, // CGNAT
		"169.254.10.20": true, // link-local
	}
	for s, want := range cases {
		v, ok := IPToUint32(mustParseIP(t, s))
		if !ok {
			t.Fatalf("IPToUint32(%s) 失败", s)
		}
		if got := IsReserved(v); got != want {
			t.Errorf("IsReserved(%s) = %v, want %v", s, got, want)
		}
	}
}

func TestTotalTargets(t *testing.T) {
	rs, err := ParseIPSpec("10.0.0.0/24", false)
	if err != nil {
		t.Fatalf("ParseIPSpec: %v", err)
	}
	if got := TotalTargets(rs, []uint16{1080, 8080}); got != 256*2 {
		t.Fatalf("got %d", got)
	}
}
