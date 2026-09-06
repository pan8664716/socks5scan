package dic

import "testing"

func TestLoadBuiltin(t *testing.T) {
	creds, err := Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(creds) != len(builtin) {
		t.Fatalf("got %d, want %d", len(creds), len(builtin))
	}
	if creds[0].User != "123456" || creds[0].Pass != "654321" {
		t.Fatalf("首条顺序被打乱: %+v", creds[0])
	}
	// 返回的是拷贝，调用方修改不应污染内置字典。
	creds[0].User = "mutated"
	if builtin[0].User == "mutated" {
		t.Fatal("Load 返回的应是拷贝")
	}
}

func TestParseRules(t *testing.T) {
	creds, err := Parse([]byte("# comment\n\nadmin:admin\nadmin:admin\nnocolonline\n:emptyuser\nuser:p:a:ss\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("去重/过滤后应剩 2 条，got %+v", creds)
	}
	if creds[1].User != "user" || creds[1].Pass != "p:a:ss" {
		t.Fatalf("口令中的冒号应保留，got %+v", creds[1])
	}
	if _, err := Parse([]byte("# only comments\n")); err == nil {
		t.Fatal("空字典应报错")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/wordlist.txt"); err == nil {
		t.Fatal("缺失文件应报错")
	}
}
