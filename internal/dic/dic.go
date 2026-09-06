// Package dic 加载弱口令字典。
//
// 字典每行一条 "user:pass"，空行与以 # 开头的行会被忽略；
// 口令部分的冒号会被保留（只按第一个冒号切分），重复行自动去重。
//
// 包内置了一份默认字典（builtin，按命中频率降序排列），
// 调用方也可以用 dic.Load(path) 指定外部文件覆盖。
package dic

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
)

// builtin 是内置的默认弱口令字典，按命中频率降序排列。
var builtin = []Cred{
	{User: "123456", Pass: "654321"},
	{User: "5555", Pass: "5555"},
	{User: "8888", Pass: "8888"},
	{User: "888", Pass: "888"},
	{User: "6666", Pass: "6666"},
	{User: "888888", Pass: "888888"},
	{User: "admin", Pass: "admin"},
	{User: "7777", Pass: "7777"},
	{User: "123456", Pass: "123456"},
	{User: "1111", Pass: "1111"},
	{User: "qwe123", Pass: "qwe123"},
	{User: "111", Pass: "111"},
	{User: "socks5", Pass: "socks5"},
	{User: "123", Pass: "123"},
	{User: "666666", Pass: "666666"},
	{User: "1234", Pass: "1234"},
	{User: "123123", Pass: "123123"},
	{User: "12345678", Pass: "12345678"},
	{User: "55555", Pass: "55555"},
	{User: "666", Pass: "666"},
	{User: "88888", Pass: "88888"},
	{User: "aaa", Pass: "aaa"},
	{User: "admin", Pass: "123456"},
	{User: "myuser", Pass: "mypassword"},
	{User: "proxyuser", Pass: "proxypass"},
	{User: "user", Pass: "123456"},
}

// Cred 是一组待尝试的用户名/口令。
type Cred struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

func (c Cred) String() string { return c.User + ":" + c.Pass }

// Load 读取字典，path 为空时使用内置字典（返回拷贝，调用方可安全修改）。
func Load(path string) ([]Cred, error) {
	if path == "" {
		out := make([]Cred, len(builtin))
		copy(out, builtin)
		return out, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取弱口令字典失败: %w", err)
	}
	return Parse(b)
}

// Parse 解析字典内容，保持文件原有顺序（高频在前）并去重。
func Parse(b []byte) ([]Cred, error) {
	var out []Cred
	seen := make(map[string]struct{})

	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		line = strings.TrimPrefix(line, "\ufeff") // 容忍 BOM
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		user, pass, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		user, pass = strings.TrimSpace(user), strings.TrimSpace(pass)
		if user == "" {
			continue
		}
		if _, dup := seen[line]; dup {
			continue
		}
		seen[line] = struct{}{}
		out = append(out, Cred{User: user, Pass: pass})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("解析弱口令字典失败: %w", err)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("弱口令字典为空")
	}
	return out, nil
}
