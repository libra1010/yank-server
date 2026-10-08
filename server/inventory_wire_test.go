package main

// 明文清单的键名和判别名是"两端各写一遍"的约定：Swift 侧 HostInventory.swift 发，
// Go 侧 inventory.go 收。这里直接把那份 Swift 源读来对字面量——改了一边忘了另一边时，
// 后果不是编译错误，而是用户页面上的清单静默变空，所以这条必须在 go test 就红。

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func swiftInventorySource(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "Sources", "TermKit", "Credentials", "HostInventory.swift")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读不到客户端清单定义 %s：%v（静默跳过会让这条变成最弱的那种绿）", path, err)
	}
	return string(raw)
}

func TestSwiftSendsTheInventoryKeyGoReads(t *testing.T) {
	src := swiftInventorySource(t)
	// Go 侧按 inventoryWireKey 取数组；Swift 侧那个常量必须逐字相同。
	if !strings.Contains(src, `wireKey = "`+inventoryWireKey+`"`) {
		t.Fatalf("客户端上传的键名与服务端读的不是一个：服务端读 %q", inventoryWireKey)
	}
}

func TestSwiftEntryFieldsAreExactlyTheWhitelist(t *testing.T) {
	src := swiftInventorySource(t)
	start := strings.Index(src, "public struct HostInventoryEntry")
	if start < 0 {
		t.Fatal("客户端里找不到 HostInventoryEntry 这个结构")
	}
	end := strings.Index(src[start:], "\n}")
	if end < 0 {
		t.Fatal("HostInventoryEntry 的结构没闭合")
	}
	body := src[start : start+end]
	// 只认带类型标注的写法会漏掉 `public var extra = ""` 这种带默认值的字段——反例试过，
	// 所以这里按"public var 后紧跟的标识符"取，类型标注有没有都算数。
	fields := regexp.MustCompile(`(?m)^\s*public var (\w+)`).FindAllStringSubmatch(body, -1)
	got := map[string]bool{}
	for _, match := range fields {
		got[match[1]] = true
	}
	if len(got) != len(inventoryWhitelist) {
		t.Fatalf("字段数对不上：客户端 %d 个，服务端白名单 %d 个（客户端=%v）",
			len(got), len(inventoryWhitelist), keysOf(got))
	}
	for want := range inventoryWhitelist {
		if !got[want] {
			t.Errorf("客户端没有 %q 这一项，服务端白名单却收它：清单会缺列", want)
		}
	}
	// 反向：客户端多发的键会在 PUT 时被整次拒绝，所以"多一个"同样是事故。
	for have := range got {
		if !inventoryWhitelist[have] {
			t.Errorf("客户端发了 %q，服务端白名单里没有：每次同步都会被 400 拒掉", have)
		}
	}
}

func TestSwiftAuthKindCodesAreTheOnesServerKeeps(t *testing.T) {
	src := swiftInventorySource(t)
	start := strings.Index(src, "static func authKind(")
	if start < 0 {
		t.Fatal("客户端里找不到 authKind 这个判别函数")
	}
	end := strings.Index(src[start:], "\n    }")
	if end < 0 {
		t.Fatal("authKind 的函数体没闭合")
	}
	codes := regexp.MustCompile(`return "([\w-]+)"`).FindAllStringSubmatch(src[start:start+end], -1)
	if len(codes) != 4 {
		t.Fatalf("判别名应当正好四个，实得 %d 个", len(codes))
	}
	for _, match := range codes {
		// clampAuthKind 认不出的一律折成 ""，界面就成了「未知」——新判别必须先在这里加。
		if clampAuthKind(match[1]) != match[1] {
			t.Errorf("客户端会发判别名 %q，但服务端 clampAuthKind 不认它，界面上只能显示未知", match[1])
		}
	}
	if clampAuthKind("publickey") != "" {
		t.Error("认不出的判别名必须折成空串，不许猜")
	}
}

func keysOf(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}
