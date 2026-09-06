// Package output 负责结果序列化。stdout 保持纯净以便管道处理，
// 所有日志与进度都输出到 stderr。
package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"

	"socks5scan/internal/scan"
)

// Format 是输出格式。
type Format int

const (
	FormatText Format = iota // socks5://IP:Port（默认，可直接喂给 curl/proxychains）
	FormatJSON               // JSON Lines
	FormatURI                // [user:pass@]IP:Port
)

// ParseFormat 解析格式名。
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "text":
		return FormatText, nil
	case "json", "jsonl":
		return FormatJSON, nil
	case "uri", "hostport":
		return FormatURI, nil
	}
	return 0, fmt.Errorf("未知输出格式 %q（可选 text|json|uri）", s)
}

// Options 控制输出细节。
type Options struct {
	Format       Format
	Verbose      bool // 附加认证方式、验证状态、出口 IP、延迟
	OnlyVerified bool // 只输出通过二次验证的
}

// Writer 是并发安全、带缓冲的结果写出器。
type Writer struct {
	mu  sync.Mutex
	buf *bufio.Writer
	enc *json.Encoder
	opt Options
	n   uint64
}

// New 构造写出器，调用方负责在结束时调用 Flush。
func New(w io.Writer, opt Options) *Writer {
	bw := bufio.NewWriterSize(w, 1<<16)
	ow := &Writer{buf: bw, opt: opt}
	if opt.Format == FormatJSON {
		ow.enc = json.NewEncoder(bw)
	}
	return ow
}

// Write 输出一条结果。
func (o *Writer) Write(r scan.Result) error {
	if o.opt.OnlyVerified && !r.Verified {
		return nil
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	var err error
	switch o.opt.Format {
	case FormatJSON:
		err = o.enc.Encode(r)
	case FormatURI:
		_, err = fmt.Fprintf(o.buf, "%s%s:%d\n", userInfo(r), r.IP, r.Port)
	default:
		_, err = io.WriteString(o.buf, o.textLine(r))
	}
	if err == nil {
		o.n++
	}
	return err
}

func (o *Writer) textLine(r scan.Result) string {
	line := fmt.Sprintf("socks5://%s%s:%d", userInfo(r), r.IP, r.Port)
	if !o.opt.Verbose {
		return line + "\n"
	}

	kind := "noauth"
	if r.Auth {
		kind = "auth"
	}
	state := "unverified"
	if r.Verified {
		state = "ok"
	}
	var extra strings.Builder
	if r.EgressIP != "" {
		fmt.Fprintf(&extra, " egress=%s", r.EgressIP)
	}
	if r.LatencyMS > 0 {
		fmt.Fprintf(&extra, " latency=%dms", r.LatencyMS)
	}
	if r.HandshakeMS > 0 {
		fmt.Fprintf(&extra, " handshake=%dms", r.HandshakeMS)
	}
	if r.Error != "" {
		fmt.Fprintf(&extra, " err=%s", r.Error)
	}
	return fmt.Sprintf("%s [%s] [%s]%s\n", line, kind, state, extra.String())
}

// userInfo 返回带 @ 的凭据前缀（已做 URL 转义），无凭据时为空串。
func userInfo(r scan.Result) string {
	if r.User == "" {
		return ""
	}
	return url.UserPassword(r.User, r.Pass).String() + "@"
}

// Count 返回已写出的条数。
func (o *Writer) Count() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.n
}

// Flush 刷出缓冲，可重复调用（扫描过程中由调用方定时调用以实现实时输出）。
func (o *Writer) Flush() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.Flush()
}
