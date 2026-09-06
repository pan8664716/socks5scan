// Package asn 实现 Python 原版的 ASN 扫描模式：
// 把 AS 号展开成它宣告的 IPv4 前缀，再交给扫描引擎遍历。
//
// 前缀来源（与 Python 的 fetch_asn_prefixes 一致）：
//  1. https://api.bgpview.io/asn/{asn}/prefixes  —— JSON data.ipv4_prefixes[].prefix
//  2. 失败则退回 https://api.hackertarget.com/aslookup/?q=AS{asn} —— 正则抓 CIDR
//
// 组织名（fetch_asn_holder）：bgpview 的 data.name，退回 stat.ripe.net 的 holder，
// 都拿不到就是「未知组织」。
package asn

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"socks5scan/internal/addr"
)

// 与 Python 一致的查询端点与超时。
const (
	bgpviewPrefixURL     = "https://api.bgpview.io/asn/%d/prefixes"
	bgpviewASNURL        = "https://api.bgpview.io/asn/%d"
	hackertargetURL      = "https://api.hackertarget.com/aslookup/?q=AS%d"
	ripeURL              = "https://stat.ripe.net/data/as-overview/data.json?resource=AS%d"
	unknownHolder        = "未知组织"
	defaultPrefixTimeout = 10 * time.Second
	defaultHolderTimeout = 5 * time.Second
	maxResponseBytes     = 8 << 20
	warnASNCount         = 100 // 与 Python calculate_total_tasks 的阈值一致
)

// Range 是一个闭区间的 ASN 区间 [Start, End]。
type Range struct {
	Start uint32
	End   uint32
}

// Count 返回区间内的 ASN 数量。
func (r Range) Count() uint64 {
	if r.End < r.Start {
		return 0
	}
	return uint64(r.End-r.Start) + 1
}

// Parse 解析 "AS13335" / "as13335" / "13335"，对应 Python 的 get_asn_from_str。
func Parse(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if len(s) > 2 && strings.EqualFold(s[:2], "AS") {
		s = strings.TrimSpace(s[2:])
	}
	if !isDigits(s) {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(v), true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// LooksLike 判断一个目标片段是否应按 ASN 解析。
// IPv4 一定带点、CIDR 一定带斜杠，所以「不含 . 与 / 且能解析成 ASN」即判为 ASN。
func LooksLike(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || strings.Contains(s, ".") || strings.Contains(s, "/") {
		return false
	}
	if i := strings.Index(s, "-"); i > 0 {
		_, ok1 := Parse(s[:i])
		_, ok2 := Parse(s[i+1:])
		return ok1 && ok2
	}
	_, ok := Parse(s)
	return ok
}

// ParseSpec 解析逗号分隔的 ASN 表达式，支持：
//
//	AS13335              单个 AS
//	AS13335-AS13400      闭区间
//	13335,13400          逗号分隔（可省略 AS 前缀）
//	@./asns.txt          从文件读取，每行一条，# 开头为注释
func ParseSpec(spec string) ([]Range, error) {
	var out []Range
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "@") {
			rs, err := parseFile(strings.TrimPrefix(part, "@"))
			if err != nil {
				return nil, err
			}
			out = append(out, rs...)
			continue
		}

		var lo, hi uint32
		if i := strings.Index(part, "-"); i > 0 {
			l, ok := Parse(part[:i])
			if !ok {
				return nil, fmt.Errorf("ASN 区间起点非法 %q", part[:i])
			}
			h, ok := Parse(part[i+1:])
			if !ok {
				return nil, fmt.Errorf("ASN 区间终点非法 %q", part[i+1:])
			}
			lo, hi = l, h
			if hi < lo {
				lo, hi = hi, lo
			}
		} else {
			v, ok := Parse(part)
			if !ok {
				return nil, fmt.Errorf("无法解析 ASN %q", part)
			}
			lo, hi = v, v
		}
		out = append(out, Range{Start: lo, End: hi})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("ASN 表达式为空: %q", spec)
	}
	return out, nil
}

func parseFile(path string) ([]Range, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("无法打开 ASN 文件: %w", err)
	}
	defer f.Close()

	var out []Range
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		txt := strings.TrimSpace(sc.Text())
		if txt == "" || strings.HasPrefix(txt, "#") {
			continue
		}
		rs, err := ParseSpec(txt)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		out = append(out, rs...)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Client 查询 ASN 的前缀与组织名，结果按 ASN 缓存（同一个 AS 只查一次）。
type Client struct {
	PrefixTimeout time.Duration
	HolderTimeout time.Duration

	mu       sync.Mutex
	prefixes map[uint32][]string
	holders  map[uint32]string
}

// New 构造查询客户端，超时 <=0 时用 Python 的默认超时（前缀 10s / 组织名 5s）。
func New(prefixTimeout, holderTimeout time.Duration) *Client {
	if prefixTimeout <= 0 {
		prefixTimeout = defaultPrefixTimeout
	}
	if holderTimeout <= 0 {
		holderTimeout = defaultHolderTimeout
	}
	return &Client{
		PrefixTimeout: prefixTimeout,
		HolderTimeout: holderTimeout,
		prefixes:      make(map[uint32][]string),
		holders:       make(map[uint32]string),
	}
}

// Prefixes 返回该 AS 宣告的 IPv4 前缀（CIDR 字符串），失败返回 error。
func (c *Client) Prefixes(asn uint32) ([]string, error) {
	c.mu.Lock()
	if v, ok := c.prefixes[asn]; ok {
		c.mu.Unlock()
		return v, nil
	}
	c.mu.Unlock()

	v, err := fetchPrefixes(asn, c.PrefixTimeout)

	c.mu.Lock()
	c.prefixes[asn] = v
	c.mu.Unlock()
	return v, err
}

// Holder 返回该 AS 的组织名，查不到时返回「未知组织」（与 Python 一致，永不失败）。
func (c *Client) Holder(asn uint32) string {
	c.mu.Lock()
	if v, ok := c.holders[asn]; ok {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()

	v := fetchHolder(asn, c.HolderTimeout)

	c.mu.Lock()
	c.holders[asn] = v
	c.mu.Unlock()
	return v
}

// PrefixRange 把一个 CIDR 前缀展开成可扫描的地址区间。
//
// 与 Python 完全一致：start = network_address + 1，end = broadcast_address - 1，
// 因此 /31、/32 这类没有可用主机位的前缀会被跳过（Python 的 range 为空）。
func PrefixRange(cidr string) (addr.Range, bool) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return addr.Range{}, false
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return addr.Range{}, false
	}
	n := uint64(1) << (32 - ones)
	if n <= 2 {
		return addr.Range{}, false
	}
	base, ok := addr.IPToUint32(ipnet.IP.To4())
	if !ok {
		return addr.Range{}, false
	}
	return addr.Range{Start: base + 1, End: base + uint32(n) - 2}, true
}

// WarnThreshold 返回 ASN 数量的告警阈值（超过时 Python 只用粗略预估）。
func WarnThreshold() uint64 { return warnASNCount }

var cidrRe = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})`)

func fetchPrefixes(asn uint32, timeout time.Duration) ([]string, error) {
	if v, err := bgpviewPrefixes(asn, timeout); err == nil {
		return v, nil
	}
	return hackertargetPrefixes(asn, timeout)
}

func bgpviewPrefixes(asn uint32, timeout time.Duration) ([]string, error) {
	body, err := get(fmt.Sprintf(bgpviewPrefixURL, asn), timeout)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Data struct {
			IPv4Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"ipv4_prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	if resp.Data.IPv4Prefixes == nil {
		return nil, fmt.Errorf("bgpview 未返回 ipv4_prefixes")
	}
	out := make([]string, 0, len(resp.Data.IPv4Prefixes))
	for _, p := range resp.Data.IPv4Prefixes {
		if p.Prefix != "" {
			out = append(out, p.Prefix)
		}
	}
	return out, nil
}

func hackertargetPrefixes(asn uint32, timeout time.Duration) ([]string, error) {
	body, err := get(fmt.Sprintf(hackertargetURL, asn), timeout)
	if err != nil {
		return nil, err
	}
	text := strings.ToLower(string(body))
	if strings.Contains(text, "error") {
		return nil, fmt.Errorf("hackertarget 返回错误: %s", strings.TrimSpace(string(body)))
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "/") {
			continue
		}
		if m := cidrRe.FindStringSubmatch(line); m != nil {
			out = append(out, m[1])
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("hackertarget 未解析到前缀")
	}
	return out, nil
}

func fetchHolder(asn uint32, timeout time.Duration) string {
	if body, err := get(fmt.Sprintf(bgpviewASNURL, asn), timeout); err == nil {
		var resp struct {
			Data struct {
				Name string `json:"name"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err == nil && resp.Data.Name != "" {
			return resp.Data.Name
		}
	}
	if body, err := get(fmt.Sprintf(ripeURL, asn), timeout); err == nil {
		var resp struct {
			Data struct {
				Holder string `json:"holder"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err == nil && resp.Data.Holder != "" {
			return resp.Data.Holder
		}
	}
	return unknownHolder
}

func get(url string, timeout time.Duration) ([]byte, error) {
	client := &http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
}
