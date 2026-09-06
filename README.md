# socks5scan

高速 SOCKS5 代理扫描器（Go）。

两级流水线：

1. **probe** —— 只做 TCP 连接 + SOCKS5 协商握手，把目标分成 关闭 / 非SOCKS5 / 需认证 / 免认证；
2. **verify** —— 对候选做完整的 CONNECT 隧道验证，可选再发 HTTP 请求探测出口 IP 与端到端延迟；需认证的目标用内置弱口令字典逐组试认证（RFC 1929）。

> 请仅对你拥有授权的网络资产使用。

## 构建

```sh
make build   # 本机平台，产物在 bin/socks5scan
make all     # 全平台（linux/darwin/windows），产物都在 bin/
```

需要 Go 1.21+。CI（`.github/workflows/build.yml`）在每次 push / PR 时自动 vet 并交叉编译全平台产物，不做定时运行。

## 用法

```sh
./bin/socks5scan -t 1.2.3.0/24 -p 1080,8080
./bin/socks5scan -t 10.0.0.0/8 -p 1024-2048 -c 5000 --only-verified -v
./bin/socks5scan -t @./cidrs.txt -p 1080 -f json -o found.jsonl
./bin/socks5scan -t AS13335 -p 1080 --only-verified
./bin/socks5scan -t AS13335-AS13400,1.2.3.0/24 -p 8888,5555 -c 3000
```

完整参数见 `./bin/socks5scan -h`。目标支持 IP / CIDR / IP 区间 / `@文件` / ASN / ASN 区间混写；扫描结果默认输出到 stdout（`--only-verified` 只输出通过端到端验证的）。

## 目录约定

- `bin/` —— 最终编译文件统一放这里（见 `Makefile` 的 `BINDIR`）；
- `results/` —— 扫描结果统一放这里，`-o` 只给文件名时自动落到该目录，带路径的按原样写入。

## 运行日志示例

`results/` 下的 `aliyun.log.example` 是一次阿里云 ASN 全量扫描的前几行日志（`--progress 10s`），展示进度行格式。
