package asn

import "testing"

func TestParse(t *testing.T) {
	for _, s := range []string{"AS13335", "as13335", "13335", "  AS13335  "} {
		v, ok := Parse(s)
		if !ok || v != 13335 {
			t.Errorf("Parse(%q) = %d,%v", s, v, ok)
		}
	}
	for _, s := range []string{"", "AS", "ASx", "1.2.3.0/24", "AS13335x"} {
		if _, ok := Parse(s); ok {
			t.Errorf("Parse(%q) 应失败", s)
		}
	}
}

func TestLooksLike(t *testing.T) {
	for _, s := range []string{"AS13335", "13335", "AS13335-AS13400", "13335-13400"} {
		if !LooksLike(s) {
			t.Errorf("LooksLike(%q) 应为 true", s)
		}
	}
	for _, s := range []string{"1.2.3.4", "10.0.0.0/8", "1.2.3.1-1.2.3.9", "@./x.txt", ""} {
		if LooksLike(s) {
			t.Errorf("LooksLike(%q) 应为 false", s)
		}
	}
}

func TestParseSpecRange(t *testing.T) {
	rs, err := ParseSpec("AS13335-AS13400,45102")
	if err != nil {
		t.Fatalf("ParseSpec: %v", err)
	}
	if len(rs) != 2 {
		t.Fatalf("got %+v", rs)
	}
	if rs[0].Start != 13335 || rs[0].End != 13400 {
		t.Errorf("got %+v", rs[0])
	}
	if c := rs[0].Count(); c != 66 {
		t.Errorf("Count = %d, want 66", c)
	}
}

func TestPrefixRange(t *testing.T) {
	r, ok := PrefixRange("192.168.1.0/30")
	if !ok {
		t.Fatal("应解析成功")
	}
	if r.Count() != 2 {
		t.Fatalf("got %+v", r)
	}
	// /31、/32 无可用主机位，应跳过。
	for _, cidr := range []string{"10.0.0.0/31", "10.0.0.1/32", "2001:db8::/32", "not-a-cidr"} {
		if _, ok := PrefixRange(cidr); ok {
			t.Errorf("PrefixRange(%q) 应为 false", cidr)
		}
	}
}
