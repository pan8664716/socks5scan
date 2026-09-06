// Package addr 负责把用户给定的目标表达式展开成可迭代的 IPv4 区间与端口列表。
//
// 全程使用 uint32 表示 IPv4，避免 net.IP 带来的堆分配与解析开销；
// 扫描引擎只需要线性递增计数器即可遍历目标空间。
package addr

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// Range 是一个闭区间的 IPv4 地址段 [Start, End]，均为网络字节序的 uint32。
type Range struct {
	Start uint32
	End   uint32
}

// Count 返回区间内的地址数量。
func (r Range) Count() uint64 {
	if r.End < r.Start {
		return 0
	}
	return uint64(r.End-r.Start) + 1
}

// IPToUint32 把 IPv4 地址转成 uint32。
func IPToUint32(ip net.IP) (uint32, bool) {
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return binary.BigEndian.Uint32(v4), true
}

// Uint32ToIP 把 uint32 还原成 4 字节的 net.IP。
func Uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}

// ParseIPSpec 解析逗号分隔的目标表达式，支持：
//
//	192.168.1.10              单个地址
//	10.0.0.0/8                CIDR
//	1.2.3.1-1.2.3.254         闭区间
//	@./targets.txt            从文件读取，每行一条，# 开头为注释
//
// trimCIDREdges 为 true 时，CIDR 的网络号与广播号会被剔除
// （/31、/32 这类没有可用主机位的除外）。
func ParseIPSpec(spec string, trimCIDREdges bool) ([]Range, error) {
	var out []Range
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		rs, err := parseOne(part, trimCIDREdges)
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("目标表达式为空: %q", spec)
	}
	return out, nil
}

func parseOne(part string, trim bool) ([]Range, error) {
	if strings.HasPrefix(part, "@") {
		return parseFile(strings.TrimPrefix(part, "@"), trim)
	}
	if strings.Contains(part, "/") {
		_, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			return nil, fmt.Errorf("无法解析 CIDR %q: %w", part, err)
		}
		r, err := cidrRange(ipnet, trim)
		if err != nil {
			return nil, err
		}
		return []Range{r}, nil
	}
	if i := strings.Index(part, "-"); i > 0 {
		lo, err := parseHost(part[:i])
		if err != nil {
			return nil, fmt.Errorf("区间起点非法 %q: %w", part[:i], err)
		}
		hi, err := parseHost(part[i+1:])
		if err != nil {
			return nil, fmt.Errorf("区间终点非法 %q: %w", part[i+1:], err)
		}
		if hi < lo {
			lo, hi = hi, lo
		}
		return []Range{{Start: lo, End: hi}}, nil
	}
	single, err := parseHost(part)
	if err != nil {
		return nil, fmt.Errorf("无法解析地址 %q: %w", part, err)
	}
	return []Range{{Start: single, End: single}}, nil
}

func parseFile(path string, trim bool) ([]Range, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("无法打开目标文件: %w", err)
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
		rs, err := ParseIPSpec(txt, trim)
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

func parseHost(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, fmt.Errorf("不是合法 IP: %q", s)
	}
	v, ok := IPToUint32(ip)
	if !ok {
		return 0, fmt.Errorf("暂不支持 IPv6: %q", s)
	}
	return v, nil
}

func cidrRange(ipnet *net.IPNet, trim bool) (Range, error) {
	base, ok := IPToUint32(ipnet.IP)
	if !ok {
		return Range{}, fmt.Errorf("CIDR 必须是 IPv4: %s", ipnet.String())
	}
	mask, ok := IPToUint32(net.IP(ipnet.Mask))
	if !ok {
		return Range{}, fmt.Errorf("CIDR 掩码非法: %s", ipnet.String())
	}
	start := base & mask
	end := start | ^mask
	// 只有存在可剔除的主机位时才做裁剪：/30 -> 2 个地址，/31、/32 保持原样。
	if trim && end-start >= 3 {
		start++
		end--
	}
	return Range{Start: start, End: end}, nil
}

// ParsePorts 解析端口表达式，支持逗号与闭区间：
//
//	1080
//	1080,8080,8888
//	1024-2048
//	80,443,8000-8100
//
// 返回值去重并保持首次出现顺序（顺序只影响扫描次序，不影响结果）。
func ParsePorts(spec string) ([]uint16, error) {
	seen := make(map[uint16]bool)
	var out []uint16

	push := func(p int) error {
		if p < 1 || p > 65535 {
			return fmt.Errorf("端口越界: %d", p)
		}
		u := uint16(p)
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
		return nil
	}

	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(strings.ReplaceAll(part, "，", ","))
		if part == "" {
			continue
		}
		if i := strings.Index(part, "-"); i > 0 {
			lo, err := strconv.Atoi(strings.TrimSpace(part[:i]))
			if err != nil {
				return nil, fmt.Errorf("端口区间起点非法 %q", part[:i])
			}
			hi, err := strconv.Atoi(strings.TrimSpace(part[i+1:]))
			if err != nil {
				return nil, fmt.Errorf("端口区间终点非法 %q", part[i+1:])
			}
			if hi < lo {
				lo, hi = hi, lo
			}
			if hi-lo > 65535 {
				return nil, fmt.Errorf("端口区间过大: %s", part)
			}
			for p := lo; p <= hi; p++ {
				if err := push(p); err != nil {
					return nil, err
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("端口非法 %q", part)
		}
		if err := push(p); err != nil {
			return nil, err
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("端口表达式为空: %q", spec)
	}
	return out, nil
}

// IsReserved 判断 IPv4 是否属于不应出现在公网的保留地址。
func IsReserved(v uint32) bool {
	b0 := byte(v >> 24)
	b1 := byte(v >> 16)
	b2 := byte(v >> 8)

	switch {
	case b0 == 0: // 0.0.0.0/8
		return true
	case b0 == 10: // 私有
		return true
	case b0 == 127: // 回环
		return true
	case b0 == 100 && b1&0xC0 == 64: // 100.64.0.0/10 CGNAT
		return true
	case b0 == 169 && b1 == 254: // link-local
		return true
	case b0 == 172 && b1&0xF0 == 16: // 私有
		return true
	case b0 == 192 && b1 == 0 && b2 == 0: // IETF 协议分配
		return true
	case b0 == 192 && b1 == 0 && b2 == 2: // TEST-NET-1
		return true
	case b0 == 192 && b1 == 168: // 私有
		return true
	case b0 == 198 && (b1 == 18 || b1 == 19): // 基准测试
		return true
	case b0 == 198 && b1 == 51 && b2 == 100: // TEST-NET-2
		return true
	case b0 == 203 && b1 == 0 && b2 == 113: // TEST-NET-3
		return true
	case b0 >= 224: // 组播 + 保留 + 实验
		return true
	}
	return false
}

// TotalTargets 估算 (地址 × 端口) 的任务总数。
func TotalTargets(ranges []Range, ports []uint16) uint64 {
	var n uint64
	for _, r := range ranges {
		n += r.Count() * uint64(len(ports))
	}
	return n
}

// SortedPorts 返回排序后的端口副本，仅用于展示。
func SortedPorts(ports []uint16) []uint16 {
	out := make([]uint16, len(ports))
	copy(out, ports)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
