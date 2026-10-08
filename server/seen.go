package main

// 「服务端这一次到底收到了什么」（#103）。
//
// 用户要的是一句能核对的话，不是一句"放心，是加密的"：开了通道密钥和没开，后端拿到的东西不
// 一样，而这一点从前只有代码知道。所以每次上传结束时服务端自己拼一句结论，既写进日志，也随
// 200 响应回给客户端 —— 客户端转述的必须是服务端的原话，不能是自己"以为对方看到了什么"。
//
// 这一句里只有字节数、条数和键名。值一个都不打印：主机名、登录账号、备注本来就存在明文清单
// 表里，管理页要看去那里看，而日志是会被拷来拷去的东西。

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// channelOutcome 是通道层那一次的三种下场。没有"解不开"这一档：那种请求在入库前就被拒了，
// 走不到这句结论。
type channelOutcome int

const (
	channelAbsent channelOutcome = iota // 客户端没带通道信封：v1 是端到端密文＋并肩数组，v2 是整包上传体
	channelNoKey                        // 带了，但服务端没配通道密钥，按不透明密文存下
	channelOpened                       // 带了并且解开了
)

// inventoryFieldNames 是明文主机清单允许出现的那几个键。白名单改了这里跟着变，因为它就是由
// 白名单算出来的，不另抄一份。
func inventoryFieldNames() []string {
	names := make([]string, 0, len(inventoryWhitelist))
	for k := range inventoryWhitelist {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// uploadSeen 是一次成功入库看到的东西。hosts/snippets 用指针是因为"客户端这一版根本没带这一
// 格"和"带了，但是空清单"是两件事：前者要说看不到，后者要说 0 条。v2/meta 只多不改：v1 那两代
// 形状的句子逐字照旧，v2 上传体才追加 secret 与账本 meta 两截说法（Swift 门禁与
// tools/sync-evidence.sh 都读这一句，结构没动）。
type uploadSeen struct {
	envelopeBytes int
	cipherBytes   int
	hosts         *int
	snippets      *int
	channel       channelOutcome
	channelRows   int
	v2            bool
	hasMeta       bool
	metaBytes     int
}

func (u uploadSeen) String() string {
	parts := []string{fmt.Sprintf(
		"信封 %d 字节（其中密文 %d 字节：同步口令只在你自己手里，这一层服务端解不开）",
		u.envelopeBytes, u.cipherBytes)}
	if u.hosts == nil {
		parts = append(parts, "没带明文主机清单：服务端看不到任何主机字段")
	} else {
		parts = append(parts, fmt.Sprintf("明文主机清单 %d 条，字段只有 %s",
			*u.hosts, strings.Join(inventoryFieldNames(), "、")))
		if u.v2 {
			parts = append(parts, "另加每行一格不透明 secret（服务端不解码、不单独落列、不从 GET 回吐）")
		}
	}
	if u.snippets == nil {
		parts = append(parts, "没带明文片段清单")
	} else {
		parts = append(parts, fmt.Sprintf("明文片段清单 %d 条", *u.snippets))
	}
	if u.v2 {
		if u.hasMeta {
			parts = append(parts, fmt.Sprintf("账本 meta 随包上行（不透明串 %d 字节，服务端不解析）",
				u.metaBytes))
		} else {
			parts = append(parts, "账本 meta：这一包没带")
		}
	}
	switch u.channel {
	case channelOpened:
		parts = append(parts, fmt.Sprintf("通道层已用通道密钥解开，读到 %d 条", u.channelRows))
	case channelNoKey:
		parts = append(parts, "通道层：客户端带了通道信封，但本机没配通道密钥，整包按不透明密文存下")
	case channelAbsent:
		parts = append(parts, "通道层：没启用（这一包不是通道信封）")
	}
	return strings.Join(parts, "；")
}

func countOf(n int) *int { return &n }

// seenOf 在入库成功之后算这一句。密文字节数：v1 信封与通道外层从共用的 `ciphertext` 字段读；
// v2 上传体顶层没有密文，就数每行 secret 与 meta 这些不透明串的字面字节 —— 那些正是这一包里
// 服务端解不开的部分。到这里形状一定已经过了闸，所以读不出来就当 0，不为一次类型抖动漏掉整句结论。
// hosts / snippets 的 nil 与空数组之分由 facts 原样带进来（nil = 这一格没带）；v1 通道清单
// （fromManifest）那份不算"带了明文清单"，句子与老口径逐字一致。
func seenOf(body []byte, facts *uploadFacts, state channelOutcome, channelRows int) uploadSeen {
	var probe struct {
		Ciphertext []byte `json:"ciphertext"`
	}
	_ = json.Unmarshal(body, &probe)
	cipherBytes := len(probe.Ciphertext)
	if cipherBytes == 0 && facts != nil && facts.v2 {
		cipherBytes = facts.secretBytes + facts.metaBytes
	}
	seen := uploadSeen{envelopeBytes: len(body), cipherBytes: cipherBytes,
		channel: state, channelRows: channelRows}
	if facts == nil || facts.fromManifest {
		return seen
	}
	if facts.hosts != nil {
		seen.hosts = countOf(len(facts.hosts))
	}
	if facts.snippets != nil {
		seen.snippets = countOf(len(facts.snippets))
	}
	if facts.v2 {
		seen.v2, seen.hasMeta, seen.metaBytes = true, facts.hasMeta, facts.metaBytes
	}
	return seen
}
