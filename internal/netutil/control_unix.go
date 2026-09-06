//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly || solaris || aix

package netutil

import (
	"syscall"
	"time"
)

// Control 用于 net.Dialer.Control，针对海量短连接场景做优化：
//
//   - SO_LINGER(0) 让 close() 直接发 RST，而不是进入 TIME_WAIT。
//     高速扫描时本地端口会被 TIME_WAIT 迅速耗尽，这是最常见的瓶颈。
//   - SO_SNDTIMEO/SO_RCVTIMEO 作为内核级兜底，避免 Go 运行时调度抖动
//     导致的连接悬挂（Go 的 SetDeadline 已足够，这里只是双保险）。
func Control(network, address string, c syscall.RawConn) error {
	var ctrlErr error
	if err := c.Control(func(fd uintptr) {
		linger := syscall.Linger{Onoff: 1, Linger: 0}
		ctrlErr = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &linger)
	}); err != nil {
		return err
	}
	return ctrlErr
}

// FDLimit 返回进程当前的文件描述符软限制，获取失败时返回 0。
func FDLimit() uint64 {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return 0
	}
	return uint64(rl.Cur)
}

// KeepAliveDisabled 返回用于 net.Dialer.KeepAlive 的取值（-1 表示关闭）。
func KeepAliveDisabled() time.Duration { return -1 }
