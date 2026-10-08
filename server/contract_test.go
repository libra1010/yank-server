package main

// 明文清单那几处"两端各写一遍"的约定（上行的键名、字段白名单、正文容量、认证方式判别名），
// 原先是直接把闭源客户端的 Swift 源读进来对字面量的。拆仓之后那条路在公开仓里走不通：
// 源码不在这个仓，镜像构建上下文里也不会有它 —— 于是 `docker build` 里的 go test 必红。
//
// 现在两边改吃一份**提交进仓的契约快照** `testdata/inventory-contract.json`：
//   · 本文件查"服务端的常量 == 快照"，任何环境（含镜像构建层）都跑得动；
//   · "快照 == 客户端源码"那一半由闭源侧的门查 —— 只有那边同时有两份文件。
// 快照读不到就当场失败，不静默跳过：跳过会让这条变成最弱的那种绿，而它管的是
// "用户页面上的清单静默变空"这种没有编译错误兜底的事故。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

type contractEntries struct {
	WireKey string   `json:"wireKey"`
	Fields  []string `json:"fields"`
}

type contractSnippets struct {
	WireKey   string   `json:"wireKey"`
	BodyLimit int      `json:"bodyLimit"`
	Fields    []string `json:"fields"`
}

type clientContract struct {
	Hosts     contractEntries  `json:"hosts"`
	Snippets  contractSnippets `json:"snippets"`
	AuthKinds []string         `json:"authKinds"`
}

func loadContract(t *testing.T) clientContract {
	t.Helper()
	path := filepath.Join("..", "testdata", "inventory-contract.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读不到客户端契约快照 %s：%v。这是提交进仓的产物（重导方式见 testdata/README.md）；"+
			"缺文件说明这一轮的上下文里没带 testdata/（镜像构建要在 Dockerfile 里 COPY 进来），"+
			"不代表这一条不用跑。", path, err)
	}
	var c clientContract
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatalf("%s 解析失败：%v", path, err)
	}
	if len(c.Hosts.Fields) == 0 || len(c.Snippets.Fields) == 0 || len(c.AuthKinds) == 0 {
		t.Fatalf("%s 里有一张表是空的：什么都比得上的快照不算快照", path)
	}
	return c
}

// 集合双向比。少一列 = 页面缺格；多一列 = PUT 时被整次 400 拒掉，两次同步都白跑。
func agreeFields(t *testing.T, what string, snapshot []string, whitelist map[string]bool) {
	t.Helper()
	have := map[string]bool{}
	for _, k := range snapshot {
		have[k] = true
	}
	if len(have) != len(snapshot) {
		t.Fatalf("%s 的快照字段表里有重复：%v", what, snapshot)
	}
	if len(have) != len(whitelist) {
		var want []string
		for k := range whitelist {
			want = append(want, k)
		}
		sort.Strings(want)
		t.Fatalf("%s 的字段数对不上：快照 %d 个，服务端白名单 %d 个（快照=%v，服务端=%v）",
			what, len(have), len(whitelist), snapshot, want)
	}
	for k := range whitelist {
		if !have[k] {
			t.Errorf("%s：服务端白名单收 %q，客户端快照里没有它 —— 清单会缺这一列", what, k)
		}
	}
	for _, k := range snapshot {
		if !whitelist[k] {
			t.Errorf("%s：客户端快照发 %q，服务端白名单里没有 —— 每次同步都会被 400 整次拒收", what, k)
		}
	}
}

func TestInventoryWireKeysMatchContract(t *testing.T) {
	c := loadContract(t)
	if c.Hosts.WireKey != inventoryWireKey {
		t.Errorf("主机清单那格的键名两端不是一个：服务端读 %q，客户端快照写 %q",
			inventoryWireKey, c.Hosts.WireKey)
	}
	if c.Snippets.WireKey != snippetInventoryWireKey {
		t.Errorf("片段清单那格的键名两端不是一个：服务端读 %q，客户端快照写 %q",
			snippetInventoryWireKey, c.Snippets.WireKey)
	}
}

func TestInventoryFieldsAreExactlyTheWhitelist(t *testing.T) {
	c := loadContract(t)
	agreeFields(t, "主机清单", c.Hosts.Fields, inventoryWhitelist)
	agreeFields(t, "片段清单", c.Snippets.Fields, snippetWhitelist)
}

// 端侧"正文太长就不展示"的容量必须不高于服务端那一格的容量：否则客户端以为自己在传完整正文，
// 服务端却把它截了 —— 而一条被截过的命令抄回去跑是另一码事。
func TestSnippetBodyLimitFitsTheServerColumn(t *testing.T) {
	c := loadContract(t)
	if c.Snippets.BodyLimit <= 0 {
		t.Fatalf("快照里的 bodyLimit = %d，不是个正数", c.Snippets.BodyLimit)
	}
	if c.Snippets.BodyLimit > snippetBodyMaxRunes {
		t.Errorf("端侧容量 %d 大于服务端那一格 %d：正文会被服务端截断而不是整条不展示",
			c.Snippets.BodyLimit, snippetBodyMaxRunes)
	}
}

func TestAuthKindCodesAreTheOnesServerKeeps(t *testing.T) {
	c := loadContract(t)
	if len(c.AuthKinds) != 4 {
		t.Fatalf("判别名应当正好四个，快照里 %d 个：%v", len(c.AuthKinds), c.AuthKinds)
	}
	for _, kind := range c.AuthKinds {
		// clampAuthKind 认不出的一律折成 ""，界面就成了「未知」—— 新增判别必须先在服务端加。
		if clampAuthKind(kind) != kind {
			t.Errorf("客户端会发判别名 %q，但服务端 clampAuthKind 不认它，界面上只能显示未知", kind)
		}
	}
	if clampAuthKind("publickey") != "" {
		t.Error("认不出的判别名必须折成空串，不许猜")
	}
}

// keysOf 给别的测试打错误信息用（原来住在被拆掉的 inventory_wire_test.go 里）。
func keysOf(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	return out
}
