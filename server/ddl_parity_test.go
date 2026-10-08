// 那两份给 DBA 复核的全量建表文件与代码里那一份 schemaStatements 的逐字比对。
//
// 为什么这条不是装饰：那两份文件头顶着"这是导出的、不是手抄副本"的名头，可这句话此前没有
// 任何机器在查 —— 2026-10-06 换 GORM 时重写了 store.go，DDL 字面量里的缩进从两格变成制表符，
// 导出件当场和代码对不上，而整套测试全绿（它比对的是列集合，不是文本）。一份"事实来源"
// 的导出件悄悄过期，比没有导出件更坏：DBA 照着它建了表，服务起来却想要另一种形状。
//
// 查的是正文（第一条 CREATE 起到文件末尾）必须与 `-ddl <方言>` 的输出逐字节相同；上面那段
// 说明性注释不参与比对，由 migrations/regenerate.sh 生成。
//
// 口径（用户 2026-10-08 拍的）：交付件只有 mysql.sql / postgres.sql 两份**全量**，
// 没有 sqlite（内嵌库由服务自己建），也没有按版本递增的增量脚本 —— 第二条测试钉住这件事。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// migrations 目录在镜像构建上下文之外（.dockerignore 只放 server/ 进去），所以在那一侧跑
// go test 时这些文件不存在。缺文件不是"通过了"，也不是"失败了"，是这一轮没得查 —— 说清楚。
const ddlDir = "../migrations"

// 交付的就是这两份。加第三方言要先有决策，加 0002-xxx.sql 那种增量直接算违例。
var ddlFiles = []string{"mysql.sql", "postgres.sql"}

func TestBaselineDDLFilesMatchCode(t *testing.T) {
	for _, name := range ddlFiles {
		kind := strings.TrimSuffix(name, ".sql")
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(ddlDir, name)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("读不到 %s：这一轮的环境里没有 migrations/（镜像构建上下文只带 server/），"+
					"这条比不了。本地跑 go test ./... 会查到。", path)
			}
			body := sqlBody(t, string(raw), path)
			var want strings.Builder
			for _, q := range schemaStatements(kind) {
				fmt.Fprintf(&want, "%s;\n", q)
			}
			if body != want.String() {
				t.Errorf("%s 的正文和代码导出的不一致：文件里那份已经过期（或 schemaStatements 改了没重导）。\n"+
					"跑一次 sh migrations/regenerate.sh 把它换回来。\n—— 文件里 ——\n%s\n—— 代码里 ——\n%s",
					path, body, want.String())
			}
		})
	}
}

// 交付目录的形状：两份全量 + 一个导出脚本，别再有第三样。
// 这一条存在的意义是"版本递增那套已经废了"，所以它得能红：往里扔一个 0002-x.sql 就该拦住。
func TestMigrationsDirHasOnlyFullDDL(t *testing.T) {
	entries, err := os.ReadDir(ddlDir)
	if err != nil {
		t.Skipf("这一轮的环境里没有 %s：本地跑 go test ./... 会查到。", ddlDir)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	want := append(append([]string{}, ddlFiles...), "regenerate.sh")
	sort.Strings(want)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("%s 里只该有 %v，实得 %v\n"+
			"增量脚本（0002-… 那种）已废：老库缺列由 Migrate() 探测补齐，交付面只出两份全量。",
			ddlDir, want, got)
	}
}

// sqlBody 取第一条 CREATE 起到末尾的那一段，正好是 -ddl 打出来的东西。
func sqlBody(t *testing.T, text, path string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "CREATE ") {
			return strings.Join(lines[i:], "\n")
		}
	}
	t.Fatalf("%s 里一条 CREATE 都没有：这份导出件被改坏了", path)
	return ""
}
