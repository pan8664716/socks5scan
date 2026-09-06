// Package probe 实现第一级"廉价预筛"：只做 TCP 连接 + SOCKS5 协商握手，
// 不发起任何真实业务流量。这是整个扫描器能跑高吞吐的关键——
// 一次探测只收发 6 个字节，即可把目标分成「关闭 / 非 SOCKS5 / 需认证 / 免认证」。
package probe

import (
	"io"
	"net"
	"strconv"
	"time"

	"socks5scan/internal/addr"
	"socks5scan/internal/netutil"
)

// Kind 描述握手结果。
type Kind uint8

const (
	Failed       Kind = iota // TCP 连接失败或超时（端口关闭 / 被过滤）
	Unknown                  // 端口开放但不是可用的 SOCKS5 服务
	AuthRequired             // SOCKS5，服务端选择「用户名/密码」认证（0x02）
	NoAuth                   // SOCKS5，服务端选择「免认证」（0x00）
)

func (k Kind) String() string {
	switch k {
	case Failed:
		return "closed"
	case Unknown:
		return "not-socks5"
	case AuthRequired:
		return "auth"
	case NoAuth:
		return "noauth"
	}
	return "unknown"
}

// DefaultGreeting 是探测用的 SOCKS5 协商报文：
//
//	VER=0x05  NMETHODS=0x02  METHODS=[0x00 免认证, 0x02 用户名/密码]
//
// 一次性声明两种方法，服务端会回一个字节告知它选了哪个，
// 据此就能区分「免认证」与「需认证」，且不会真的进入认证流程。
var DefaultGreeting = []byte{0x05, 0x02, 0x00, 0x02}

// Outcome 是一次探测的结果。
type Outcome struct {
	Kind     Kind
	Elapsed  time.Duration // 从发起 connect 到读完协商响应的总耗时
	Accepted byte          // 服务端选中的方法字节，用于排障
}

// Prober 执行握手探测。
type Prober struct {
	DialTimeout time.Duration // TCP connect 超时
	ReadTimeout time.Duration // 等待协商响应的超时（connect 之后单独计时）
	Greeting    []byte        // 为空时使用 DefaultGreeting
}

// Probe 对 ip:port 做一次 SOCKS5 握手探测，绝不会 panic，也不会泄漏连接。
func (p *Prober) Probe(ip uint32, port uint16) Outcome {
	target := net.JoinHostPort(addr.Uint32ToIP(ip).String(), strconv.Itoa(int(port)))
	greeting := p.Greeting
	if len(greeting) == 0 {
		greeting = DefaultGreeting
	}

	d := net.Dialer{
		Timeout:   p.DialTimeout,
		KeepAlive: netutil.KeepAliveDisabled(),
		Control:   netutil.Control,
	}

	start := time.Now()
	conn, err := d.Dial("tcp4", target)
	if err != nil {
		return Outcome{Kind: Failed, Elapsed: time.Since(start)}
	}
	defer conn.Close()

	// 连接已建立，重新设定握手读超时（通常比 connect 超时更短）。
	if err := conn.SetDeadline(time.Now().Add(p.ReadTimeout)); err != nil {
		return Outcome{Kind: Unknown, Elapsed: time.Since(start)}
	}
	if _, err := conn.Write(greeting); err != nil {
		return Outcome{Kind: Unknown, Elapsed: time.Since(start)}
	}

	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return Outcome{Kind: Unknown, Elapsed: time.Since(start)}
	}
	elapsed := time.Since(start)

	// 服务端必须回 VER=0x05，否则认为不是 SOCKS5。
	if hdr[0] != 0x05 {
		return Outcome{Kind: Unknown, Elapsed: elapsed, Accepted: hdr[1]}
	}

	switch hdr[1] {
	case 0x00:
		return Outcome{Kind: NoAuth, Elapsed: elapsed, Accepted: hdr[1]}
	case 0x02:
		return Outcome{Kind: AuthRequired, Elapsed: elapsed, Accepted: hdr[1]}
	default:
		// 0xFF 表示「无可用方法」，其余为未知方法。
		return Outcome{Kind: Unknown, Elapsed: elapsed, Accepted: hdr[1]}
	}
}
