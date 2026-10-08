package main

// 「服务端这一次收到了什么」（#103）。
//
// 用户要的是能核对的一句话：通道密钥开着还是没开，后端拿到的东西必须各自说清楚，而且这句话
// 要回到客户端屏幕上，不是只躺在日志里。这一组检查盯三件事：
//   1. 两种模式得到的句子确实不一样（不是同一句套话）；
//   2. 句子里只有字节数、条数、键名 —— 主机地址、账号、口令一个值都不许出现；
//   3. "没带明文清单"和"带了但是 0 条"分得开，否则老客户端会被说成新客户端。

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// putSeen 发一次上传并取回服务端自己写的那句结论。
func putSeen(t *testing.T, e *env, body []byte) string {
	t.Helper()
	res, raw := e.putBlob(body, "0")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("上传应成功：%d %s", res.StatusCode, raw)
	}
	var reply struct {
		Revision int64  `json:"revision"`
		Seen     string `json:"seen"`
	}
	if err := json.Unmarshal(raw, &reply); err != nil {
		t.Fatalf("响应不是合法 JSON：%v %s", err, raw)
	}
	if reply.Revision != 1 {
		t.Errorf("修订号应照旧回出来（新增字段不许挤掉老的）：%d", reply.Revision)
	}
	if reply.Seen == "" {
		t.Fatalf("响应里没有 seen 这一句：%s", raw)
	}
	return reply.Seen
}

func TestSeenSentenceWithoutChannelKey(t *testing.T) {
	e := inventoryEnv(t) // 不带 -channel-key
	seen := putSeen(t, e, bodyWithInventory(t, twoHostInventory))
	for _, want := range []string{"明文主机清单 2 条", "通道层：没启用", "同步口令只在你自己手里"} {
		if !strings.Contains(seen, want) {
			t.Errorf("端到端这一包该说「%s」：%s", want, seen)
		}
	}
	if strings.Contains(seen, "解开") {
		t.Errorf("没配通道密钥时不许出现「解开」：%s", seen)
	}
	// 反例：这一句会被贴进日志、贴进聊天。值一个都不能带。
	for _, leak := range []string{"10.0.0.1", "build.lan", "root", "devops", "机房A", fakePassword} {
		if strings.Contains(seen, leak) {
			t.Errorf("结论里漏了清单的值「%s」：%s", leak, seen)
		}
	}
}

func TestSeenSentenceWithChannelKey(t *testing.T) {
	e, _, _ := newChanEnv(t, chanA)
	seen := putSeen(t, e, sealManifest(t, chanA, twoHostManifest(t)))
	if !strings.Contains(seen, "通道层已用通道密钥解开，读到 2 条") {
		t.Errorf("开了通道密钥要说解开了几条：%s", seen)
	}
	// 这一包只有通道层，没带并肩的明文清单 —— 两个来源不能混着说。
	if !strings.Contains(seen, "没带明文主机清单") {
		t.Errorf("通道信封不该被说成带了明文清单：%s", seen)
	}
	for _, leak := range []string{"jump.example.com", "nas.lan", "devops", fakePassword} {
		if strings.Contains(seen, leak) {
			t.Errorf("结论里漏了通道里的值「%s」：%s", leak, seen)
		}
	}
}

func TestSeenSentenceChannelEnvelopeWithoutServerKey(t *testing.T) {
	// 客户端开了通道、服务端没配密钥：这一包按不透明密文存下，而这句话必须说明白，
	// 不能两边都以为"加密传输在工作"。
	e := inventoryEnv(t)
	seen := putSeen(t, e, sealManifest(t, chanA, twoHostManifest(t)))
	if !strings.Contains(seen, "带了通道信封") || !strings.Contains(seen, "按不透明密文存下") {
		t.Errorf("要说清「带了但本机没配密钥」：%s", seen)
	}
	if strings.Contains(seen, "解开") {
		t.Errorf("没配密钥就没有解开这回事：%s", seen)
	}
}

func TestSeenSentenceSeparatesEmptyFromAbsentInventory(t *testing.T) {
	e := inventoryEnv(t)
	empty := putSeen(t, e, bodyWithInventory(t, `[]`))
	if !strings.Contains(empty, "明文主机清单 0 条") {
		t.Errorf("带了空数组要说 0 条：%s", empty)
	}
	// 另起一台干净的服务器：putSeen 报的都是第 0 版，同一台第二次上传会被 409 挡下。
	plain := putSeen(t, inventoryEnv(t), envelopeBody(t, `{"revision":1,"profiles":[]}`))
	if !strings.Contains(plain, "没带明文主机清单") {
		t.Errorf("老客户端没带清单，不能说成 0 条：%s", plain)
	}
}

func TestSeenSentenceCountsCiphertextBytes(t *testing.T) {
	body := bodyWithInventory(t, twoHostInventory)
	seen := uploadSeen{envelopeBytes: len(body), cipherBytes: 4096,
		channel: channelAbsent}.String()
	if !strings.Contains(seen, "信封 "+strconv.Itoa(len(body))+" 字节") ||
		!strings.Contains(seen, "密文 4096 字节") {
		t.Errorf("字节数要摊开写：%s", seen)
	}
	if !strings.Contains(seen, "服务端看不到任何主机字段") {
		t.Errorf("没清单时要把话说到底：%s", seen)
	}
}
