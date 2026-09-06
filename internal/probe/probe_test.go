package probe

import (
	"net"
	"testing"
	"time"
)

// startFakeSocks5 起一个最小 SOCKS5 服务端：读 greeting 后按 method 应答。
func startFakeSocks5(t *testing.T, method byte) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 257)
				n, err := conn.Read(buf)
				if err != nil || n < 3 {
					return
				}
				_, _ = conn.Write([]byte{0x05, method})
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

func probeAddr(t *testing.T, target string) (uint32, uint16) {
	t.Helper()
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("bad test addr %s", target)
	}
	var v uint32
	for _, b := range ip {
		v = v<<8 | uint32(b)
	}
	var p uint16
	for _, c := range port {
		p = p*10 + uint16(c-'0')
	}
	return v, p
}

func TestProbeNoAuth(t *testing.T) {
	target, done := startFakeSocks5(t, 0x00)
	defer done()
	ip, port := probeAddr(t, target)
	out := (&Prober{DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second}).Probe(ip, port)
	if out.Kind != NoAuth {
		t.Fatalf("got %v", out.Kind)
	}
}

func TestProbeAuthRequired(t *testing.T) {
	target, done := startFakeSocks5(t, 0x02)
	defer done()
	ip, port := probeAddr(t, target)
	out := (&Prober{DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second}).Probe(ip, port)
	if out.Kind != AuthRequired {
		t.Fatalf("got %v", out.Kind)
	}
}

func TestProbeClosedPort(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	target := ln.Addr().String()
	_ = ln.Close()
	ip, port := probeAddr(t, target)
	out := (&Prober{DialTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second}).Probe(ip, port)
	if out.Kind != Failed {
		t.Fatalf("关闭端口应为 Failed，got %v", out.Kind)
	}
}

// 非 SOCKS5 服务（只 accept 不回包）应判为 Unknown 而非 hang 住。
func TestProbeNonSocks5(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 64)
				_, _ = conn.Read(buf) // 读完 greeting，但永远不回包
				time.Sleep(2 * time.Second)
			}(c)
		}
	}()
	ip, port := probeAddr(t, ln.Addr().String())
	out := (&Prober{DialTimeout: 2 * time.Second, ReadTimeout: 300 * time.Millisecond}).Probe(ip, port)
	if out.Kind != Unknown {
		t.Fatalf("got %v", out.Kind)
	}
}
