package addr

import (
	"net"
	"testing"
)

func mustParseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("非法测试 IP: %s", s)
	}
	return ip
}
