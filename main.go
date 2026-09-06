// Command socks5scan 是一个高速 SOCKS5 代理扫描器。
//
// 两级流水线：
//
//	第一级 probe  —— 只做 TCP 连接 + SOCKS5 协商握手（共 6 字节），
//	                 把目标分成 关闭 / 非SOCKS5 / 需认证 / 免认证。
//	第二级 verify —— 对候选做完整的 CONNECT 隧道验证，
//	                 可选地再发一个 HTTP 请求探测出口 IP 与端到端延迟；
//	                 若目标要求认证，则用弱口令字典逐组试认证（RFC 1929），
//	                 命中后同样走完整的隧道验证。
//
// 说明：请仅对你拥有授权的网络资产使用。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"socks5scan/internal/addr"
	"socks5scan/internal/asn"
	"socks5scan/internal/dic"
	"socks5scan/internal/netutil"
	"socks5scan/internal/output"
	"socks5scan/internal/scan"
	"socks5scan/internal/verify"
)

// 默认值与 Python 原版（proxy-scanner-socks5-key-5.py）对齐：
// 端口 1080,8080,8888,1088,8000,9999,1473；并发 3000；TIMEOUT=4s。
//
// 默认端口 = Python 原版（1080,8080,8888,1088,8000,9999,1473）
//   - Go 原版（1081,1085,3128,9050）
//   - /root/test/data/proxyip 实测高频端口（5555,6666,7777）
//
// 整体按 proxyip 实测命中数降序：8888:482 / 5555:285 / 1080:223 / 6666:93 / 8080:42 / 7777:38。
// 编译产物统一放到 bin/（见 Makefile 的 BINDIR），
// 扫描结果统一放到 results/（见 resolveOutPath）。
const defaultPorts = "8888,5555,1080,6666,8080,7777,1088,8000,9999,1473,1081,1085,3128,9050"

// resultsDir 是扫描结果输出文件的统一存放目录：-o 只给文件名时落到这里。
const resultsDir = "results"

type options struct {
	target string
	ports  string

	concurrency       int
	verifyConcurrency int
	dialTimeout       time.Duration
	readTimeout       time.Duration

	verify        bool
	verifyHost    string
	verifyPort    int
	verifyPath    string
	verifyTimeout time.Duration
	egress        bool

	weak        bool
	wordlist    string
	authTimeout time.Duration
	asnTimeout  time.Duration

	skipReserved bool
	randomize    bool
	rate         int
	seed         int64

	format       string
	out          string
	verbose      bool
	onlyVerified bool
	progress     time.Duration
	dryRun       bool
	includeEdges bool
}

func main() {
	opts := parseFlags()
	if err := run(opts); err != nil {
		fmt.Fprintf(os.Stderr, "[error] %v\n", err)
		os.Exit(1)
	}
}

// 下面三个辅助函数同时注册短名与长名（短名为空则只注册长名），
// 共用一个变量与使用说明，避免重复注册导致的 panic。
func str(p *string, short, long, def, usage string) {
	if short != "" {
		flag.StringVar(p, short, def, usage)
	}
	flag.StringVar(p, long, def, usage)
}

func int_(p *int, short, long string, def int, usage string) {
	if short != "" {
		flag.IntVar(p, short, def, usage)
	}
	flag.IntVar(p, long, def, usage)
}

func bool_(p *bool, short, long string, def bool, usage string) {
	if short != "" {
		flag.BoolVar(p, short, def, usage)
	}
	flag.BoolVar(p, long, def, usage)
}

func parseFlags() *options {
	o := &options{}

	str(&o.target, "t", "target", "", "扫描目标：IP / CIDR / IP区间 / 逗号分隔 / @文件")
	str(&o.ports, "p", "ports", defaultPorts, "端口表达式，如 1080,8080 或 1024-2048")

	int_(&o.concurrency, "c", "concurrency", 3000, "探测并发数（Python 版默认 3000）")
	int_(&o.verifyConcurrency, "", "verify-concurrency", 0, "验证并发数（默认 = 探测并发/20，与 Python 的 5% 一致）")
	flag.DurationVar(&o.dialTimeout, "timeout", 4*time.Second, "TCP connect 超时（Python TIMEOUT=4s）")
	flag.DurationVar(&o.readTimeout, "read-timeout", 1*time.Second, "SOCKS5 协商响应超时（Python 硬编码 1.0s）")

	bool_(&o.verify, "", "verify", true, "对免认证候选做端到端验证")
	noVerify := flag.Bool("no-verify", false, "--verify 的取反写法")
	str(&o.verifyHost, "", "verify-host", "", "验证时的 CONNECT 目标主机")
	int_(&o.verifyPort, "", "verify-port", 0, "验证时的 CONNECT 目标端口（默认 80）")
	str(&o.verifyPath, "", "verify-path", "", "出口 IP 探测的 HTTP 路径（默认 /ip）")
	flag.DurationVar(&o.verifyTimeout, "verify-timeout", 8*time.Second, "单次验证的墙钟超时（含两次 HTTP 校验，各 4s）")
	bool_(&o.egress, "", "egress", true, "验证时探测出口 IP（依赖外部回显服务）")
	noEgress := flag.Bool("no-egress", false, "--egress 的取反写法")

	bool_(&o.weak, "", "weak", true, "对需认证代理用弱口令字典做验证")
	noWeak := flag.Bool("no-weak", false, "--weak 的取反写法")
	str(&o.wordlist, "w", "wordlist", "", "弱口令字典文件（默认使用内置字典）")
	flag.DurationVar(&o.authTimeout, "auth-timeout", 8*time.Second, "单次弱口令认证尝试的超时（每次同样跑两次 HTTP 校验）")
	flag.DurationVar(&o.asnTimeout, "asn-timeout", 10*time.Second, "ASN 前缀/组织名查询超时（Python 为 10s/5s）")

	bool_(&o.skipReserved, "", "skip-reserved", true, "跳过私有/保留地址段")
	bool_(&o.randomize, "", "randomize", true, "打乱扫描顺序，降低对单一网段的瞬时压力")
	int_(&o.rate, "", "rate", 0, "每秒任务数上限，0 表示不限")
	flag.Int64Var(&o.seed, "seed", 0, "随机种子，0 表示用当前时间")

	str(&o.format, "f", "format", "text", "输出格式 text|json|uri")
	str(&o.out, "o", "out", "", "结果输出文件（默认 stdout；只给文件名时写入 results/ 目录）")
	bool_(&o.verbose, "v", "verbose", false, "输出认证方式/验证状态/出口 IP/延迟")
	flag.BoolVar(&o.onlyVerified, "only-verified", false, "只输出通过端到端验证的代理")
	flag.DurationVar(&o.progress, "progress", 5*time.Second, "进度打印间隔，0 关闭")
	flag.BoolVar(&o.dryRun, "dry-run", false, "只统计任务总量后退出，不发包")
	flag.BoolVar(&o.includeEdges, "include-edges", false, "CIDR 保留网络号与广播号")

	flag.Usage = usage
	flag.Parse()

	o.applyDerived(*noVerify, *noEgress, *noWeak)
	return o
}

// applyDerived 处理互斥开关与默认值推导。
func (o *options) applyDerived(noVerify, noEgress, noWeak bool) {
	explicit := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { explicit[f.Name] = true })

	// --no-verify / --no-egress / --no-weak 是对应开关的取反写法。
	if noVerify {
		o.verify = false
	}
	if noEgress {
		o.egress = false
	}
	if noWeak {
		o.weak = false
	}

	if o.verifyPort == 0 {
		o.verifyPort = 80
	}
	if o.verifyPath == "" {
		o.verifyPath = "/ip"
	}
	// 验证目标默认取 Python 版的主回显服务 httpbin.org/ip。
	if !explicit["verify-host"] {
		if o.egress {
			o.verifyHost = verify.DefaultHost
			o.verifyPort = verify.DefaultPort
		} else {
			o.verifyHost = "1.1.1.1"
			o.verifyPort = 80
		}
	}
}

func (o *options) validate() error {
	if strings.TrimSpace(o.target) == "" {
		return fmt.Errorf("必须用 -t/--target 指定扫描目标")
	}
	if o.concurrency < 1 {
		return fmt.Errorf("并发数必须 >= 1")
	}
	if o.dialTimeout <= 0 || o.readTimeout <= 0 {
		return fmt.Errorf("超时必须为正数")
	}
	if o.verifyPort < 1 || o.verifyPort > 65535 {
		return fmt.Errorf("验证端口越界: %d", o.verifyPort)
	}
	if o.verifyConcurrency < 0 {
		return fmt.Errorf("验证并发不能为负")
	}
	if o.verify && strings.TrimSpace(o.verifyHost) == "" {
		return fmt.Errorf("开启验证时必须指定 --verify-host")
	}
	return nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `socks5scan - 高速 SOCKS5 代理扫描器

用法:
  socks5scan -t <目标> [选项]

目标表达式 (-t):
  1.2.3.4                单个地址
  10.0.0.0/8             CIDR
  1.2.3.1-1.2.3.254      闭区间
  1.2.3.0/24,5.6.7.0/24  逗号分隔
  @./targets.txt         从文件读取（每行一条，# 注释）
  AS13335                按 ASN 扫描（自动拉该 AS 的 IPv4 前缀）
  AS13335-AS13400        ASN 区间
  1.2.3.0/24,AS13335     IP 与 ASN 可混写

端口表达式 (-p):
  1080,8080              枚举
  1024-2048              区间
  80,443,8000-8100       混合
  默认: 8888,5555,1080,6666,8080,7777,1088,8000,9999,1473,1081,1085,3128,9050

扫描参数:
  -c, --concurrency N         探测并发（默认 3000，与 Python 版一致）
      --verify-concurrency N  验证并发（默认 = 探测并发/20，同 Python 的 5%%）
      --timeout D             TCP connect 超时（默认 4s，同 Python TIMEOUT）
      --read-timeout D        SOCKS5 协商响应超时（默认 1s，同 Python 硬编码值）
      --rate N                每秒任务数上限（0 不限）
      --randomize             打乱扫描顺序（默认开启）
      --skip-reserved         跳过私有/保留地址（默认开启）
      --include-edges         CIDR 保留网络号与广播号

验证参数:
      --verify / --no-verify  是否做端到端验证（默认开启）
      --egress / --no-egress  是否探测出口 IP（默认开启，需外部回显服务）
      --verify-host H         主回显服务（默认 httpbin.org；--no-egress 时为 1.1.1.1）
      --verify-port P         主回显服务端口（默认 80）
      --verify-path P         主回显服务的 HTTP 路径（默认 /ip）
      --verify-timeout D      单次验证的墙钟超时（默认 8s，含两次 HTTP 校验）

二次校验固定为 info.cern.ch + 关键字 WorldWideWeb（同 Python 原版），
两个请求都返回 200 且关键字命中才算可用。

ASN 参数:
      --asn-timeout D       ASN 前缀/组织名查询超时（默认 10s）
                            前缀来源: api.bgpview.io → 退回 api.hackertarget.com
                            组织名来源: api.bgpview.io → 退回 stat.ripe.net
                            每个前缀展开为 [network+1, broadcast-1]，/31、/32 跳过

弱口令参数（针对「需认证」的 SOCKS5）:
      --weak / --no-weak     是否用弱口令字典逐组试认证（默认开启）
  -w, --wordlist FILE        弱口令字典，每行 user:pass（默认使用内置字典）
      --auth-timeout D       单次认证尝试的超时（默认 8s）

「需认证」以及「免认证但二次验证失败」的目标都会进弱口令队列（同 Python 原版）；
爆破未命中的目标只计数、不输出。

输出参数:
  -f, --format text|json|uri  输出格式（默认 text）
  -o, --out FILE              结果写入文件（默认 stdout；只给文件名时写入 results/）
  -v, --verbose               输出认证方式/验证状态/出口 IP/延迟
      --only-verified         只输出通过端到端验证的
      --progress D            进度打印间隔（默认 5s，0 关闭）
      --dry-run               只统计任务总量后退出

示例:
  socks5scan -t 1.2.3.0/24 -p 1080,8080
  socks5scan -t 10.0.0.0/8 -p 1024-2048 -c 5000 --only-verified -v
  socks5scan -t @./cidrs.txt -p 1080 -f json -o found.jsonl
  socks5scan -t 203.0.113.0/24 --no-egress --verify-host 1.1.1.1 --verify-port 80
  socks5scan -t 1.2.3.0/24 -p 1080 -w ./my.txt --only-verified
  socks5scan -t AS13335 -p 1080 --only-verified
  socks5scan -t AS13335-AS13400,1.2.3.0/24 -p 8888,5555 -c 3000

提示: 扫描结果输出到 stdout，日志与进度输出到 stderr。
      高并发行前建议先执行: ulimit -n 100000
`)
}

// splitTarget 把 -t 表达式按逗号拆成「IP 片段」与「ASN 片段」，@文件会递归展开。
//
// 判定规则与 Python 一致：能解析成 ASN（AS13335 / 13335）且不含点或斜杠的按 ASN 处理，
// 其余交给 addr 包解析成地址区间。
func splitTarget(spec string) (ips, asns []string, err error) {
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, "@") {
			blob, rerr := os.ReadFile(strings.TrimPrefix(part, "@"))
			if rerr != nil {
				return nil, nil, fmt.Errorf("无法打开目标文件: %w", rerr)
			}
			for _, line := range strings.Split(string(blob), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				subIPs, subASNs, serr := splitTarget(line)
				if serr != nil {
					return nil, nil, serr
				}
				ips = append(ips, subIPs...)
				asns = append(asns, subASNs...)
			}
			continue
		}
		if asn.LooksLike(part) {
			asns = append(asns, part)
			continue
		}
		ips = append(ips, part)
	}
	return ips, asns, nil
}

// expandTargets 把 -t 展开成可直接遍历的地址区间：
// IP / CIDR / 区间走 addr 包，ASN 走 asn 包在线拉前缀后展开。
func (o *options) expandTargets() ([]addr.Range, error) {
	ipParts, asnParts, err := splitTarget(o.target)
	if err != nil {
		return nil, err
	}

	var ranges []addr.Range
	if len(ipParts) > 0 {
		rs, err := addr.ParseIPSpec(strings.Join(ipParts, ","), !o.includeEdges)
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, rs...)
	}
	if len(asnParts) == 0 {
		if len(ranges) == 0 {
			return nil, fmt.Errorf("目标表达式为空: %q", o.target)
		}
		return ranges, nil
	}

	specs, err := asn.ParseSpec(strings.Join(asnParts, ","))
	if err != nil {
		return nil, err
	}

	var asnCount uint64
	for _, r := range specs {
		asnCount += r.Count()
	}
	if asnCount > asn.WarnThreshold() {
		fmt.Fprintf(os.Stderr, "[warn] ASN 范围过大 (%d 个)，前缀查询会较慢\n", asnCount)
	}

	client := asn.New(o.asnTimeout, o.asnTimeout)
	prefixes := 0
	for _, r := range specs {
		for a := r.Start; a <= r.End; a++ {
			fmt.Fprintf(os.Stderr, "[ASN] 扫描 AS%d - %s\n", a, client.Holder(a))

			ps, err := client.Prefixes(a)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[warn] AS%d 前缀获取失败: %v\n", a, err)
			}
			for _, p := range ps {
				if rr, ok := asn.PrefixRange(p); ok {
					ranges = append(ranges, rr)
					prefixes++
				}
			}
			if a == math.MaxUint32 {
				break
			}
		}
	}
	fmt.Fprintf(os.Stderr, "[ASN] %d 个 AS 共展开 %d 个前缀\n", asnCount, prefixes)

	if len(ranges) == 0 {
		return nil, fmt.Errorf("ASN 未展开出任何可扫描的地址: %q", o.target)
	}
	return ranges, nil
}

func run(o *options) error {
	if err := o.validate(); err != nil {
		return err
	}

	ranges, err := o.expandTargets()
	if err != nil {
		return err
	}
	ports, err := addr.ParsePorts(o.ports)
	if err != nil {
		return err
	}

	total := addr.TotalTargets(ranges, ports)
	var addrs uint64
	for _, r := range ranges {
		addrs += r.Count()
	}

	vc := o.verifyConcurrency
	if vc == 0 {
		vc = o.concurrency / 20
		if vc < 1 {
			vc = 1
		}
	}

	if o.dryRun {
		fmt.Fprintf(os.Stderr, "目标: %d 个网段 / %d 个地址 / %d 个端口 => %d 个任务\n",
			len(ranges), addrs, len(ports), total)
		return nil
	}

	if lim := netutil.FDLimit(); lim > 0 && uint64(o.concurrency) > lim-128 {
		fmt.Fprintf(os.Stderr, "[warn] 并发 %d 接近文件描述符上限 %d，建议先执行 ulimit -n 100000\n",
			o.concurrency, lim)
	}

	// 输出目标：-o 为空走 stdout；只给文件名（不含路径分隔符）时
	// 统一落到 results/ 目录；带路径的按原样写入。
	var sink io.Writer = os.Stdout
	outPath := ""
	if o.out != "" {
		outPath = resolveOutPath(o.out)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return fmt.Errorf("无法创建输出目录: %w", err)
		}
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("无法创建输出文件: %w", err)
		}
		defer f.Close()
		sink = f
	}

	format, err := output.ParseFormat(o.format)
	if err != nil {
		return err
	}
	writer := output.New(sink, output.Options{
		Format:       format,
		Verbose:      o.verbose,
		OnlyVerified: o.onlyVerified,
	})

	// 结果实时刷出，方便 tail -f 边扫边看（结束时再刷一次兜底）。
	stopFlush := make(chan struct{})
	flushDone := make(chan struct{})
	defer func() {
		close(stopFlush)
		<-flushDone
	}()
	go func() {
		defer close(flushDone)
		tk := time.NewTicker(time.Second)
		defer tk.Stop()
		for {
			select {
			case <-stopFlush:
				return
			case <-tk.C:
				_ = writer.Flush()
			}
		}
	}()

	// 弱口令字典：默认使用代码内置字典。
	var creds []dic.Cred
	if o.weak {
		var err error
		if creds, err = dic.Load(o.wordlist); err != nil {
			return err
		}
	}

	engine := scan.New(scan.Config{
		Ranges:            ranges,
		Ports:             ports,
		Concurrency:       o.concurrency,
		VerifyConcurrency: vc,
		DialTimeout:       o.dialTimeout,
		ReadTimeout:       o.readTimeout,
		Verify:            o.verify,
		VerifyOpts: verify.Options{
			Timeout: o.verifyTimeout,
			Host:    o.verifyHost,
			Port:    uint16(o.verifyPort),
			Path:    o.verifyPath,
			Egress:  o.egress,
			// 二次校验目标留空即用包内默认值（info.cern.ch + 关键字）。
		},
		Auth:         o.weak && len(creds) > 0,
		Weak:         creds,
		AuthTimeout:  o.authTimeout,
		SkipReserved: o.skipReserved,
		Randomize:    o.randomize,
		Rate:         o.rate,
		Seed:         o.seed,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	verifyDesc := "关"
	if o.verify {
		verifyDesc = fmt.Sprintf("开(%s:%d)", o.verifyHost, o.verifyPort)
		if o.egress {
			verifyDesc += "+出口IP"
		}
	}
	if o.weak {
		verifyDesc += fmt.Sprintf(" | 弱口令 %d 组", len(creds))
	}
	fmt.Fprintf(os.Stderr,
		"[start] %d 地址 x %d 端口 = %d 任务 | 探测并发 %d | 验证并发 %d | connect %s | 验证 %s\n",
		addrs, len(ports), total, o.concurrency, vc, o.dialTimeout, verifyDesc)

	// 进度上报（stderr，不污染结果流）。
	if o.progress > 0 {
		ticker := time.NewTicker(o.progress)
		done := make(chan struct{})
		defer func() { close(done); ticker.Stop() }()
		go func() {
			for {
				select {
				case <-done:
					return
				case <-ctx.Done():
					return
				case <-ticker.C:
					s := engine.Stats()
					fmt.Fprintf(os.Stderr,
						"[progress] 已探 %d (%.0f/s) 跳过保留 %d 免认证 %d 需认证 %d 非socks5 %d 关闭 %d 验证成功 %d 弱口令命中 %d 写出 %d\n",
						s.Scanned, s.Rate(), s.Skipped, s.NoAuth, s.AuthRequired, s.NotSocks5, s.Closed,
						s.VerifyOK, s.WeakOK, writer.Count())
				}
			}
		}()
	}

	stats := engine.Run(ctx, func(r scan.Result) {
		if err := writer.Write(r); err != nil {
			fmt.Fprintf(os.Stderr, "[warn] 写入结果失败: %v\n", err)
		}
	})

	if err := writer.Flush(); err != nil {
		return fmt.Errorf("刷出结果失败: %w", err)
	}

	fmt.Fprintf(os.Stderr,
		"[done] 已探 %d | 跳过保留 %d | 免认证 %d | 需认证 %d | 非socks5 %d | 关闭 %d | 验证成功 %d | 验证失败 %d | 弱口令命中 %d | 弱口令未中 %d | 写出 %d | 耗时 %s | 均速 %.0f/s\n",
		stats.Scanned, stats.Skipped, stats.NoAuth, stats.AuthRequired, stats.NotSocks5, stats.Closed,
		stats.VerifyOK, stats.VerifyFail, stats.WeakOK, stats.WeakFail, writer.Count(),
		stats.Elapsed.Round(time.Millisecond), stats.Rate())

	if o.out != "" {
		fmt.Fprintf(os.Stderr, "[done] 结果已写入 %s\n", outPath)
	}
	return nil
}

// resolveOutPath 统一扫描结果的落盘位置：
// o 为空保持为空；不含路径分隔符的纯文件名拼到 results/ 下；
// 其它（相对/绝对路径）按原样返回。
func resolveOutPath(o string) string {
	if o == "" {
		return ""
	}
	if !strings.ContainsAny(o, `/\`) {
		return filepath.Join(resultsDir, o)
	}
	return o
}
