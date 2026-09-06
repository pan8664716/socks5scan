// Package scan 是并发扫描引擎。
//
// 设计要点（取自原始 Python 版的分级思路，但用 goroutine 取代线程池）：
//
//  1. 目标空间由单个 generator goroutine 生产，走带缓冲的 jobs channel，
//     天然形成背压：探测慢就自动降速，不会把目标全量物化到内存。
//  2. 大量 probe worker 只做 6 字节的握手探测，成本极低、并发可开很高。
//  3. 命中「免认证 SOCKS5」的候选被投递到小得多的 verify worker 池，
//     避免昂贵的端到端验证拖慢探测吞吐。
//  4. 「需认证 SOCKS5」的候选、以及「免认证但二次验证失败」的候选，
//     都进入同一个 verify worker 池，由弱口令字典逐组试认证（RFC 1929），
//     命中即做完整的两次 HTTP 校验（与 Python 原版一致）。
//  5. ctx 取消即可中止，已在飞行中的任务最多跑完当前一个。
package scan

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"socks5scan/internal/addr"
	"socks5scan/internal/dic"
	"socks5scan/internal/probe"
	"socks5scan/internal/verify"
)

// Result 是一条有效发现。
type Result struct {
	IP          string `json:"ip"`
	Port        uint16 `json:"port"`
	Auth        bool   `json:"auth_required"`
	Verified    bool   `json:"verified"`
	User        string `json:"username,omitempty"`
	Pass        string `json:"password,omitempty"`
	EgressIP    string `json:"egress_ip,omitempty"`
	HandshakeMS int64  `json:"handshake_ms,omitempty"`
	LatencyMS   int64  `json:"latency_ms,omitempty"`
	Error       string `json:"error,omitempty"`
}

// Config 驱动引擎。
type Config struct {
	Ranges            []addr.Range
	Ports             []uint16
	Concurrency       int            // 探测并发
	VerifyConcurrency int            // 验证并发（应远小于探测并发）
	DialTimeout       time.Duration  // TCP connect 超时
	ReadTimeout       time.Duration  // 握手读取超时
	Verify            bool           // 是否做二次验证
	VerifyOpts        verify.Options // 二次验证参数
	Auth              bool           // 是否对「需认证」代理做弱口令验证
	Weak              []dic.Cred     // 弱口令字典，按优先级排列
	AuthTimeout       time.Duration  // 单次认证尝试的墙钟超时，<=0 时沿用 VerifyOpts.Timeout
	SkipReserved      bool           // 跳过保留/私有地址
	Randomize         bool           // 打乱扫描顺序
	Rate              int            // 每秒任务数上限，0 表示不限
	Seed              int64          // 随机种子，0 表示用时间
}

type task struct {
	ip           uint32
	port         uint16
	handshake    time.Duration
	authRequired bool // 该目标要求用户名/密码认证
}

// Engine 持有一次扫描的全部状态。Run 之后可继续调用 Stats 读取计数。
type Engine struct {
	cfg    Config
	prober *probe.Prober
	rng    *rand.Rand

	jobs    chan task
	verifyQ chan task
	out     chan Result

	wg  sync.WaitGroup
	vwg sync.WaitGroup

	scanned   uint64
	noauth    uint64
	authreq   uint64
	notsocks5 uint64
	closed    uint64
	verifyOK  uint64
	verifyBad uint64
	weakOK    uint64
	weakBad   uint64
	skipped   uint64
	start     time.Time
}

// New 构造引擎并填充默认值。
func New(cfg Config) *Engine {
	if cfg.Concurrency < 1 {
		cfg.Concurrency = 1
	}
	if cfg.VerifyConcurrency < 1 {
		cfg.VerifyConcurrency = 1
	}
	seed := cfg.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	return &Engine{
		cfg:    cfg,
		prober: &probe.Prober{DialTimeout: cfg.DialTimeout, ReadTimeout: cfg.ReadTimeout},
		rng:    rand.New(rand.NewSource(seed)),
	}
}

// Stats 是计数快照。
type Stats struct {
	Scanned      uint64
	NoAuth       uint64
	AuthRequired uint64
	NotSocks5    uint64
	Closed       uint64
	VerifyOK     uint64
	VerifyFail   uint64
	WeakOK       uint64 // 弱口令命中（并完成两次 HTTP 校验）
	WeakFail     uint64 // 弱口令全部未命中
	Skipped      uint64 // 保留地址跳过数（Python 计入 completed）
	Elapsed      time.Duration
}

// Rate 返回每秒完成的任务数。
func (s Stats) Rate() float64 {
	sec := s.Elapsed.Seconds()
	if sec <= 0 {
		return 0
	}
	return float64(s.Scanned) / sec
}

// Stats 读取当前计数快照。
func (e *Engine) Stats() Stats {
	return Stats{
		Scanned:      atomic.LoadUint64(&e.scanned),
		NoAuth:       atomic.LoadUint64(&e.noauth),
		AuthRequired: atomic.LoadUint64(&e.authreq),
		NotSocks5:    atomic.LoadUint64(&e.notsocks5),
		Closed:       atomic.LoadUint64(&e.closed),
		VerifyOK:     atomic.LoadUint64(&e.verifyOK),
		VerifyFail:   atomic.LoadUint64(&e.verifyBad),
		WeakOK:       atomic.LoadUint64(&e.weakOK),
		WeakFail:     atomic.LoadUint64(&e.weakBad),
		Skipped:      atomic.LoadUint64(&e.skipped),
		Elapsed:      time.Since(e.start),
	}
}

// Run 执行扫描，每条发现同步回调 sink（串行调用，无需加锁）。
// 返回最终计数。ctx 取消后 Run 会尽快返回。
func (e *Engine) Run(ctx context.Context, sink func(Result)) Stats {
	conc := e.cfg.Concurrency
	vconc := e.cfg.VerifyConcurrency

	e.start = time.Now()
	e.jobs = make(chan task, conc*2)
	e.verifyQ = make(chan task, vconc*8+16)
	e.out = make(chan Result, 4096)

	// 结果收集 goroutine：保证 sink 串行执行。
	var collect sync.WaitGroup
	collect.Add(1)
	go func() {
		defer collect.Done()
		for r := range e.out {
			if sink != nil {
				sink(r)
			}
		}
	}()

	e.wg.Add(conc)
	for i := 0; i < conc; i++ {
		go e.probeWorker(ctx)
	}
	e.vwg.Add(vconc)
	for i := 0; i < vconc; i++ {
		go e.verifyWorker(ctx)
	}

	var limiter <-chan time.Time
	if e.cfg.Rate > 0 {
		d := time.Duration(float64(time.Second) / float64(e.cfg.Rate))
		if d <= 0 {
			d = time.Microsecond
		}
		tk := time.NewTicker(d)
		defer tk.Stop()
		limiter = tk.C
	}

	go e.generate(ctx, limiter)

	e.wg.Wait()      // 所有探测任务结束
	close(e.verifyQ) // 通知验证池收尾
	e.vwg.Wait()
	close(e.out)
	collect.Wait()

	return e.Stats()
}

// generate 生产 (ip, port) 任务。
//
// 随机化不落地整个目标集：先打乱区间顺序，再为每个区间取一个随机起点
// 做环形遍历——既保证全覆盖，又无需 O(n) 内存。
func (e *Engine) generate(ctx context.Context, limiter <-chan time.Time) {
	defer close(e.jobs)

	ranges := make([]addr.Range, len(e.cfg.Ranges))
	copy(ranges, e.cfg.Ranges)
	ports := make([]uint16, len(e.cfg.Ports))
	copy(ports, e.cfg.Ports)

	if e.cfg.Randomize {
		if len(ranges) > 1 {
			e.rng.Shuffle(len(ranges), func(i, j int) { ranges[i], ranges[j] = ranges[j], ranges[i] })
		}
		if len(ports) > 1 {
			e.rng.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
		}
	}

	for _, r := range ranges {
		size := r.Count()
		if size == 0 {
			continue
		}
		var offset uint64
		if e.cfg.Randomize && size > 1 {
			offset = uint64(e.rng.Int63n(int64(size)))
		}
		for i := uint64(0); i < size; i++ {
			// r 是合法区间，Start + (size-1) 不会溢出 uint32。
			v := r.Start + uint32((offset+i)%size)
			if e.cfg.SkipReserved && addr.IsReserved(v) {
				// Python 在探测前判断 is_private 并计入 completed，这里同样计数。
				atomic.AddUint64(&e.skipped, uint64(len(ports)))
				continue
			}
			for _, p := range ports {
				if limiter != nil {
					select {
					case <-ctx.Done():
						return
					case <-limiter:
					}
				}
				select {
				case <-ctx.Done():
					return
				case e.jobs <- task{ip: v, port: p}:
				}
			}
		}
	}
}

func (e *Engine) probeWorker(ctx context.Context) {
	defer e.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case t, ok := <-e.jobs:
			if !ok {
				return
			}
			e.probeOne(ctx, t)
		}
	}
}

func (e *Engine) probeOne(ctx context.Context, t task) {
	out := e.prober.Probe(t.ip, t.port)
	atomic.AddUint64(&e.scanned, 1)

	switch out.Kind {
	case probe.NoAuth:
		atomic.AddUint64(&e.noauth, 1)
	case probe.AuthRequired:
		atomic.AddUint64(&e.authreq, 1)
		t.handshake = out.Elapsed
		// 需认证的代理无法匿名验证：开了弱口令验证就送去试口令，
		// 否则照旧作为「发现」直接输出。
		if e.cfg.Auth && len(e.cfg.Weak) > 0 {
			t.authRequired = true
			select {
			case <-ctx.Done():
				return
			case e.verifyQ <- t:
				return
			}
		}
		e.emit(Result{
			IP:          addr.Uint32ToIP(t.ip).String(),
			Port:        t.port,
			Auth:        true,
			HandshakeMS: out.Elapsed.Milliseconds(),
		})
		return
	case probe.Unknown:
		atomic.AddUint64(&e.notsocks5, 1)
		return
	default:
		atomic.AddUint64(&e.closed, 1)
		return
	}

	t.handshake = out.Elapsed
	if e.cfg.Verify {
		select {
		case <-ctx.Done():
			return
		case e.verifyQ <- t:
			return
		}
	}
	e.emit(Result{
		IP:          addr.Uint32ToIP(t.ip).String(),
		Port:        t.port,
		HandshakeMS: t.handshake.Milliseconds(),
	})
}

func (e *Engine) verifyWorker(ctx context.Context) {
	defer e.vwg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case t, ok := <-e.verifyQ:
			if !ok {
				return
			}
			e.verifyOne(t)
		}
	}
}

func (e *Engine) verifyOne(t task) {
	if t.authRequired {
		e.crackOne(t, true)
		return
	}

	res := verify.Check(t.ip, t.port, e.cfg.VerifyOpts)
	r := Result{
		IP:          addr.Uint32ToIP(t.ip).String(),
		Port:        t.port,
		HandshakeMS: t.handshake.Milliseconds(),
	}
	if res.OK {
		atomic.AddUint64(&e.verifyOK, 1)
		r.Verified = true
		r.EgressIP = res.EgressIP
		r.LatencyMS = res.Latency.Milliseconds()
		if res.Error != "" {
			r.Error = res.Error
		}
		e.emit(r)
		return
	}

	atomic.AddUint64(&e.verifyBad, 1)

	// 与 Python 一致：免认证但二次验证失败的目标，同样丢进弱口令爆破队列。
	if e.cfg.Auth && len(e.cfg.Weak) > 0 {
		e.crackOne(t, false)
		return
	}

	// 没开弱口令验证时，照旧输出「疑似可用但没通过验证」的目标。
	r.Error = res.Error
	e.emit(r)
}

// crackOne 对目标按字典顺序逐组试认证，命中即停。
//
// 与 Python 的 run_auth_brute_force 保持一致：任何一次失败（口令错误、
// 超时、出口校验失败）都只是换下一组，直到把整份字典试完；只有命中才输出，
// 全都没中则只累计计数、不写结果文件。
func (e *Engine) crackOne(t task, authRequired bool) {
	opts := e.cfg.VerifyOpts
	if e.cfg.AuthTimeout > 0 {
		opts.Timeout = e.cfg.AuthTimeout
	}

	ip := addr.Uint32ToIP(t.ip).String()
	for _, c := range e.cfg.Weak {
		opts.User, opts.Pass = c.User, c.Pass
		res := verify.Check(t.ip, t.port, opts)
		if !res.OK {
			continue
		}
		atomic.AddUint64(&e.weakOK, 1)
		r := Result{
			IP:          ip,
			Port:        t.port,
			Auth:        authRequired,
			Verified:    true,
			User:        c.User,
			Pass:        c.Pass,
			EgressIP:    res.EgressIP,
			LatencyMS:   res.Latency.Milliseconds(),
			HandshakeMS: t.handshake.Milliseconds(),
		}
		if res.Error != "" {
			r.Error = res.Error
		}
		e.emit(r)
		return
	}

	// Python 原版只打一条「弱密码验证失败」日志，不写结果文件。
	atomic.AddUint64(&e.weakBad, 1)
}

func (e *Engine) emit(r Result) {
	e.out <- r
}
