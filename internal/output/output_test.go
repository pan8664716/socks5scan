package output

import (
	"bytes"
	"strings"
	"testing"

	"socks5scan/internal/scan"
)

func sample() scan.Result {
	return scan.Result{IP: "1.2.3.4", Port: 1080, Verified: true, EgressIP: "5.6.7.8", LatencyMS: 120, HandshakeMS: 30}
}

func TestTextFormat(t *testing.T) {
	var buf bytes.Buffer
	w := New(&buf, Options{Format: FormatText})
	if err := w.Write(sample()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got := strings.TrimSpace(buf.String()); got != "socks5://1.2.3.4:1080" {
		t.Fatalf("got %q", got)
	}
	if w.Count() != 1 {
		t.Fatalf("Count = %d", w.Count())
	}
}

func TestTextVerboseIncludesAuthAndEgress(t *testing.T) {
	var buf bytes.Buffer
	w := New(&buf, Options{Format: FormatText, Verbose: true})
	r := sample()
	r.Auth, r.User, r.Pass = true, "u", "p"
	if err := w.Write(r); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	line := buf.String()
	for _, want := range []string{"socks5://u:p@1.2.3.4:1080", "[auth]", "[ok]", "egress=5.6.7.8"} {
		if !strings.Contains(line, want) {
			t.Errorf("缺少 %q，got %q", want, line)
		}
	}
}

func TestOnlyVerifiedFilters(t *testing.T) {
	var buf bytes.Buffer
	w := New(&buf, Options{Format: FormatText, OnlyVerified: true})
	if err := w.Write(scan.Result{IP: "1.2.3.4", Port: 1080}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if buf.Len() != 0 || w.Count() != 0 {
		t.Fatalf("未验证结果应被过滤，got %q count=%d", buf.String(), w.Count())
	}
}

func TestJSONFormatOneLine(t *testing.T) {
	var buf bytes.Buffer
	w := New(&buf, Options{Format: FormatJSON})
	if err := w.Write(sample()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	line := strings.TrimSpace(buf.String())
	if !strings.Contains(line, `"ip":"1.2.3.4"`) || !strings.Contains(line, `"verified":true`) {
		t.Fatalf("got %q", line)
	}
}

func TestParseFormat(t *testing.T) {
	if f, _ := ParseFormat("jsonl"); f != FormatJSON {
		t.Error("jsonl 应映射到 JSON")
	}
	if f, _ := ParseFormat("hostport"); f != FormatURI {
		t.Error("hostport 应映射到 URI")
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("未知格式应报错")
	}
}
