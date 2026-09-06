# socks5scan

[English](README.md) · [更新日志](CHANGELOG.md) · [贡献指南](CONTRIBUTING.md) · [Releases](https://github.com/pan8664716/socks5scan/releases)

高速 SOCKS5 代理扫描器（Go，两级流水线）。

**工作原理：**

1. **probe（预筛）** —— 只做 TCP 连接 + SOCKS5 协商握手（共 6 字节），把目标分成
   `关闭 / 非SOCKS5 / 需认证 / 免认证`；
2. **verify（验证）** —— 对候选做完整的 CONNECT 隧道验证，可选再发 HTTP 请求探测出口 IP
   与端到端延迟；要求认证的目标用内置弱口令字典逐组试认证（RFC 1929）。

> ⚠️ **请仅对你拥有授权的网络资产使用。** 未授权扫描可能违法，详见 [SECURITY.md](SECURITY.md)。

## 特性

- 🎯 灵活的目标表达式：单个 IP、CIDR、IP 区间、逗号分隔、`@文件`、ASN（`AS13335`）、
  ASN 区间，可自由混写
- 🔌 灵活的端口表达式：枚举与区间（如 `1080,8080`、`1024-2048`）
- ⚡ 高吞吐引擎：生成器 → 探测池 → 验证池三级流水线，自带背压
- ✅ 双 HTTP 交叉验证（过滤只返回假页面的代理）
- 🔑 内置弱口令字典，可用 `-w` 指定外部字典覆盖
- 📄 三种输出格式：`text`（`socks5://…`）、`json`（JSON Lines）、`uri`（`[user:pass@]ip:port`）
- 🖥️ 全平台二进制：Linux / macOS / Windows（amd64 + arm64）

## 安装

从 [Releases](https://github.com/pan8664716/socks5scan/releases) 下载预编译二进制，
或从源码构建（需要 Go 1.21+）：

```sh
git clone https://github.com/pan8664716/socks5scan.git
cd socks5scan
make build   # 本机平台，产物在 bin/socks5scan
make all     # 全平台，产物都在 bin/
```

## 快速开始

```sh
# 扫一个 /24，只看通过验证的代理
./bin/socks5scan -t 1.2.3.0/24 --only-verified -v

# 多目标 + 自定义端口
./bin/socks5scan -t 10.0.0.0/8 -p 1024-2048 -c 5000 --only-verified -v

# 从文件读目标，JSON 结果写到 results/
./bin/socks5scan -t @./cidrs.txt -p 1080 -f json -o found.jsonl

# 按 ASN 扫（自动拉取该 AS 的 IPv4 前缀）
./bin/socks5scan -t AS13335 -p 1080 --only-verified

# 只验证隧道是否打通，不做 HTTP 校验
./bin/socks5scan -t 203.0.113.0/24 --no-egress --verify-host 1.1.1.1 --verify-port 80
```

完整参数见 `./bin/socks5scan -h`。

## 验证机制

只有走完完整链条的候选才算**已验证可用**：

1. SOCKS5 握手（服务端要求认证时按 RFC 1929 做用户名/密码认证）；
2. 向主回显服务（默认 `httpbin.org/ip`）建 CONNECT 隧道；
3. 再向第二个独立站点 `info.cern.ch` 发起校验，要求 HTTP 200 且正文含关键字——
   过滤只回显假页面的代理。

`--no-egress` 可跳过 HTTP 校验、只验证隧道；`--verify-host/--verify-port/--verify-path`
可把验证指向你自己的回显服务（大规模扫描时推荐，避免给公共服务造成压力）。

## 性能调优

实际吞吐通常受限于带宽、NAT 表大小和默认 4s 的 connect 超时，而不是 CPU：

| 场景 | 建议 |
| ---- | ---- |
| 家庭宽带 | `-c 3000`（默认），路由器吃力就调低 |
| 云主机 1Gbps+ | `-c 5000`–`10000` |
| 需要限速 | `--rate 1000` |
| 先估算规模 | `--dry-run`（不发包） |

调高并发前先调大文件描述符上限：

```sh
ulimit -n 100000
```

并发接近 fd 上限时程序会在 stderr 打印告警。

## 输出说明

- 结果默认输出到 **stdout**（方便管道处理）；日志与 `[progress]` 进度行输出到 **stderr**。
- `-o FILE`：结果写入文件。只给文件名时落到 `results/`（如 `-o found.jsonl` →
  `results/found.jsonl`）；带路径的按原样写入。
- `-f text|json|uri`、`-v`（认证方式/验证状态/出口 IP/延迟）、
  `--only-verified`（只输出通过验证的）。
- `results/aliyun.log.example` 是一次 `--progress 10s` 的 stderr 日志样例。

## 项目结构

```text
.
├── main.go                  # CLI：参数解析、目标展开、输出装配
├── internal/
│   ├── addr/                # 目标/端口表达式解析、私有保留地址判断
│   ├── asn/                 # ASN -> IPv4 前缀展开（bgpview/hackertarget/RIPE）
│   ├── dic/                 # 弱口令字典（内置 + -w 外部文件）
│   ├── probe/               # 第一级：6 字节握手预筛
│   ├── verify/              # 第二级：CONNECT 隧道 + 双 HTTP 校验
│   ├── scan/                # 流水线引擎（生成器/探测池/验证池）
│   ├── output/              # text/json/uri 序列化
│   └── netutil/             # socket 调优（SO_LINGER、fd 上限）
├── bin/                     # 编译产物（见 Makefile BINDIR）
└── results/                 # 扫描结果（见 -o 参数）
```

## 开发

```sh
gofmt -l .     # 必须无输出
make vet
make test
```

PR 流程见 [CONTRIBUTING.md](CONTRIBUTING.md)。用户可见的变更请记入
[CHANGELOG.md](CHANGELOG.md)。

## 许可证

[MIT](LICENSE)
