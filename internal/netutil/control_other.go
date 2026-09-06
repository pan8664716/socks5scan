//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || aix)

package netutil

import (
	"syscall"
	"time"
)

// Control 在没有 SO_LINGER 可用 SDK 的平台上是空操作。
// 这些平台上请自行调低并发或调大临时端口范围。
func Control(network, address string, c syscall.RawConn) error { return nil }

// FDLimit 返回 0 表示无法探测。
func FDLimit() uint64 { return 0 }

// KeepAliveDisabled 返回用于 net.Dialer.KeepAlive 的取值（-1 表示关闭）。
func KeepAliveDisabled() time.Duration { return -1 }
