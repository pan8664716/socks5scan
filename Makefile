# socks5scan 构建入口：最终编译文件统一放到 bin/。
GO      ?= go
MODULE  := socks5scan
BINDIR  := bin
BIN     := $(BINDIR)/socks5scan
LDFLAGS := -s -w
GOFLAGS ?=

.PHONY: all build linux darwin windows clean vet test help

# 默认：本机平台构建。
build: $(BIN)

$(BIN):
	mkdir -p $(BINDIR)
	$(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) .

# 全平台编译产物（都落在 bin/ 下）。
all: linux darwin windows

linux:
	mkdir -p $(BINDIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(MODULE)-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(MODULE)-linux-arm64 .

darwin:
	mkdir -p $(BINDIR)
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(MODULE)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(MODULE)-darwin-arm64 .

windows:
	mkdir -p $(BINDIR)
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(MODULE)-windows-amd64.exe .

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

clean:
	find $(BINDIR) -mindepth 1 ! -name '.gitkeep' -delete

help:
	@echo "targets: build(默认本机) all linux darwin windows vet test clean"
	@echo "产物目录: $(BINDIR)/   扫描结果目录: results/"
