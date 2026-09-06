// Package verify 实现第二级"真实可用性验证"。
//
// 只有通过了 probe 预筛的候选才会走到这里，因此成本可以忽略不计。
// 流程与 Python 原版保持一致：完整的 SOCKS5 协商（必要时按 RFC 1929 做
// 用户名/密码认证）+ CONNECT 建隧道，然后连发两个 HTTP 请求做交叉校验：
//
//  1. httpbin.org/ip  —— 取出口 IP（JSON 里的 origin 字段，取逗号前第一段）
//  2. info.cern.ch    —— 响应 200 且正文含关键字，过滤"假回显"代理
//
// 两个请求都成功才算可用；Latency 统计的是两次请求的总耗时（与 Python 一致）。
// 认证被服务端拒绝时返回 ErrBadCred，便于上层继续尝试下一组弱口令。
package verify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"socks5scan/internal/addr"
	"socks5scan/internal/netutil"
)

// Python 原版的两个校验目标（TEST_URL / SECONDARY_HTTP_URL / SECONDARY_KEYWORD）。
const (
	DefaultHost             = "httpbin.org"
	DefaultPort             = 80
	DefaultPath             = "/ip"
	DefaultSecondaryHost    = "info.cern.ch"
	DefaultSecondaryPort    = 80
	DefaultSecondaryPath    = "/hypertext/WWW/TheProject.html"
	DefaultSecondaryKeyword = "WorldWideWeb"

	defaultTimeout = 8 * time.Second // 两个 HTTP 请求，每个 4s（Python TIMEOUT=4）
	maxBody        = 64 * 1024
	userAgent      = "socks5scan/1.0"
)

var (
	// ErrAuthRequired 表示代理要求用户名/密码认证，当前未提供凭据。
	ErrAuthRequired = errors.New("socks5: 需要用户名/密码认证")
	// ErrBadCred 表示代理拒绝了本次用户名/密码认证（口令错误）。
	ErrBadCred = errors.New("socks5: 用户名或密码错误")
)

// Options 配置二次验证行为。
type Options struct {
	Timeout time.Duration // 整个验证（含两次 HTTP 校验）的墙钟超时
	Host    string        // 主回显服务的主机名
	Port    uint16        // 主回显服务的端口
	Path    string        // 主回显服务的 HTTP 路径
	Egress  bool          // 是否发起两次 HTTP 校验（关闭时只验证 CONNECT 隧道）
	User    string        // 用户名（留空则只做免认证验证）
	Pass    string        // 口令

	SecondaryHost    string // 二次校验主机名
	SecondaryPort    uint16 // 二次校验端口
	SecondaryPath    string // 二次校验路径
	SecondaryKeyword string // 二次校验必须出现的关键字
}

func (o Options) withDefaults() Options {
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.Host == "" {
		o.Host = DefaultHost
	}
	if o.Port == 0 {
		o.Port = DefaultPort
	}
	if o.Path == "" {
		o.Path = DefaultPath
	}
	if o.SecondaryHost == "" {
		o.SecondaryHost = DefaultSecondaryHost
	}
	if o.SecondaryPort == 0 {
		o.SecondaryPort = DefaultSecondaryPort
	}
	if o.SecondaryPath == "" {
		o.SecondaryPath = DefaultSecondaryPath
	}
	if o.SecondaryKeyword == "" {
		o.SecondaryKeyword = DefaultSecondaryKeyword
	}
	return o
}

// Result 是验证结果。
type Result struct {
	OK       bool          // 两次校验都通过（或 --no-egress 时隧道打通）
	EgressIP string        // 代理的公网出口 IP，可能为空
	Latency  time.Duration // 从 connect 到两次校验完成的总延迟
	BadCred  bool          // 认证被拒绝（用户名/口令错误），可换下一组继续
	Error    string        // 失败原因（成功时为空）
}

// Check 通过指定的 SOCKS5 代理发起两次 HTTP 校验，任何错误都以 Result 返回，不会 panic。
func Check(ip uint32, port uint16, opts Options) Result {
	opts = opts.withDefaults()
	target := net.JoinHostPort(addr.Uint32ToIP(ip).String(), strconv.Itoa(int(port)))
	start := time.Now()
	deadline := start.Add(opts.Timeout)

	// 阶段一：主回显服务，拿出口 IP。
	c1, err := openTunnel(target, deadline, opts, opts.Host, opts.Port)
	if err != nil {
		return fail(err)
	}
	defer c1.Close()

	if !opts.Egress {
		// 只验证隧道本身（--no-egress，Go 版独有的简化）。
		return Result{OK: true, Latency: time.Since(start)}
	}

	status, body, err := httpGet(c1, opts.Host, opts.Path)
	if err != nil {
		return fail(fmt.Errorf("回显请求失败: %w", err))
	}
	if status != 200 {
		return fail(fmt.Errorf("回显服务状态码 %d", status))
	}
	origin, err := parseOrigin(body)
	if err != nil {
		return fail(err)
	}

	// 阶段二：换一个站点再校验一次，过滤只回显假页面的代理。
	c2, err := openTunnel(target, deadline, opts, opts.SecondaryHost, opts.SecondaryPort)
	if err != nil {
		return fail(err)
	}
	defer c2.Close()

	status2, body2, err := httpGet(c2, opts.SecondaryHost, opts.SecondaryPath)
	if err != nil {
		return fail(fmt.Errorf("二次校验请求失败: %w", err))
	}
	if status2 != 200 {
		return fail(fmt.Errorf("二次校验状态码 %d", status2))
	}
	if !bytes.Contains(bytes.ToLower(body2), bytes.ToLower([]byte(opts.SecondaryKeyword))) {
		return fail(fmt.Errorf("二次校验缺少关键字 %q", opts.SecondaryKeyword))
	}

	return Result{OK: true, EgressIP: origin, Latency: time.Since(start)}
}

// fail 把错误转成 Result，认证失败单独打标，便于上层换下一组口令重试。
func fail(err error) Result {
	if errors.Is(err, ErrBadCred) {
		return Result{Error: err.Error(), BadCred: true}
	}
	return Result{Error: err.Error()}
}

// openTunnel 建连 → 协商（必要时认证）→ CONNECT 到 host:port，返回已就绪的隧道。
func openTunnel(target string, deadline time.Time, opts Options, host string, port uint16) (net.Conn, error) {
	budget := time.Until(deadline)
	if budget <= 0 {
		return nil, fmt.Errorf("验证超时")
	}

	d := net.Dialer{
		Timeout:   budget,
		KeepAlive: netutil.KeepAliveDisabled(),
		Control:   netutil.Control,
	}
	conn, err := d.Dial("tcp4", target)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, fmt.Errorf("deadline: %w", err)
	}
	if err := handshake(conn, opts); err != nil {
		conn.Close()
		return nil, err
	}

	req, err := buildConnect(host, port)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("connect-req: %w", err)
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connect-write: %w", err)
	}
	if err := readReply(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connect-reply: %w", err)
	}
	return conn, nil
}

// handshake 做 SOCKS5 方法协商，服务端选 0x02 时按 RFC 1929 认证。
func handshake(conn net.Conn, opts Options) error {
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		return fmt.Errorf("greeting-read: %w", err)
	}
	if sel[0] != 0x05 {
		return fmt.Errorf("非 SOCKS5 响应 (ver=0x%02x)", sel[0])
	}
	switch sel[1] {
	case 0x00:
		return nil // 免认证
	case 0x02:
		if opts.User == "" && opts.Pass == "" {
			return ErrAuthRequired
		}
		return authUserPass(conn, opts.User, opts.Pass)
	default:
		return fmt.Errorf("不支持的认证方法 (0x%02x)", sel[1])
	}
}

// authUserPass 执行 RFC 1929 用户名/密码子协商。
// 认证被服务端拒绝时返回包装了 ErrBadCred 的错误，便于上层用 errors.Is 判断。
func authUserPass(conn net.Conn, user, pass string) error {
	if len(user) == 0 || len(user) > 255 {
		return fmt.Errorf("用户名长度非法: %d", len(user))
	}
	if len(pass) > 255 {
		return fmt.Errorf("口令长度非法: %d", len(pass))
	}

	req := make([]byte, 0, 3+len(user)+len(pass))
	req = append(req, 0x01, byte(len(user)))
	req = append(req, user...)
	req = append(req, byte(len(pass)))
	req = append(req, pass...)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return err
	}
	if resp[0] != 0x01 {
		return fmt.Errorf("认证响应版本错误 (0x%02x)", resp[0])
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("%w (status=0x%02x)", ErrBadCred, resp[1])
	}
	return nil
}

// httpGet 在已建立的隧道上发一个 HTTP/1.0 请求，返回状态码与响应体。
// 用 1.0 是为了避开 chunked 编码，服务端响应完直接关连接。
func httpGet(conn net.Conn, host, path string) (int, []byte, error) {
	if path == "" {
		path = "/"
	}
	req := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n", path, host, userAgent)
	if _, err := conn.Write([]byte(req)); err != nil {
		return 0, nil, err
	}

	raw, err := io.ReadAll(io.LimitReader(conn, maxBody))
	if err != nil && len(raw) == 0 {
		return 0, nil, err
	}
	idx := bytes.Index(raw, []byte("\r\n\r\n"))
	if idx < 0 {
		return 0, nil, fmt.Errorf("HTTP 响应不完整")
	}
	head, body := raw[:idx], raw[idx+4:]

	line := head
	if i := bytes.IndexByte(head, '\n'); i >= 0 {
		line = head[:i]
	}
	fields := strings.Fields(string(line))
	if len(fields) < 2 {
		return 0, nil, fmt.Errorf("HTTP 状态行异常: %q", string(line))
	}
	code, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, nil, fmt.Errorf("HTTP 状态码异常: %q", fields[1])
	}
	return code, body, nil
}

// parseOrigin 从回显服务响应里取出口 IP，取逗号前第一段（与 Python 一致）。
// JSON 解析失败即判定验证失败——拿不到出口 IP 的代理不算可用。
func parseOrigin(body []byte) (string, error) {
	var payload struct {
		Origin string `json:"origin"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("出口 IP 解析失败: %w", err)
	}
	return strings.TrimSpace(strings.Split(payload.Origin, ",")[0]), nil
}

// buildConnect 构造 SOCKS5 CONNECT 请求，自动选择域名(0x03)或 IPv4(0x01)形式。
func buildConnect(host string, port uint16) ([]byte, error) {
	pb := []byte{byte(port >> 8), byte(port)}

	if ip := net.ParseIP(host); ip != nil {
		v4 := ip.To4()
		if v4 == nil {
			return nil, fmt.Errorf("CONNECT 目标不支持 IPv6: %s", host)
		}
		out := make([]byte, 0, 10)
		out = append(out, 0x05, 0x01, 0x00, 0x01)
		out = append(out, v4...)
		return append(out, pb...), nil
	}

	if host == "" || len(host) > 255 {
		return nil, fmt.Errorf("CONNECT 目标域名非法: %q", host)
	}
	out := make([]byte, 0, 4+1+len(host)+2)
	out = append(out, 0x05, 0x01, 0x00, 0x03, byte(len(host)))
	out = append(out, host...)
	return append(out, pb...), nil
}

// readReply 读取并校验 SOCKS5 CONNECT 响应，消费掉 BND.ADDR/BND.PORT。
func readReply(conn net.Conn) error {
	hdr := make([]byte, 4) // VER REP RSV ATYP
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("响应版本错误 (0x%02x)", hdr[0])
	}
	if hdr[1] != 0x00 {
		return fmt.Errorf("CONNECT 被拒绝 (rep=0x%02x)", hdr[1])
	}

	var tail int
	switch hdr[3] {
	case 0x01:
		tail = 4 + 2 // IPv4 + port
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		tail = int(l[0]) + 2 // 域名 + port
	case 0x04:
		tail = 16 + 2 // IPv6 + port
	default:
		return fmt.Errorf("未知地址类型 (atyp=0x%02x)", hdr[3])
	}
	rest := make([]byte, tail)
	_, err := io.ReadFull(conn, rest)
	return err
}
