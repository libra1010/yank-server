// 那三份给 DBA 复核的建表文件与代码里那一份 schemaStatements 的逐字比对。
//
// 为什么这条不是装饰：那三份文件头顶着"这是导出的、不是手抄副本"的名头，可这句话此前没有
// 任何机器在查 —— 2026-10-06 换 GORM 时重写了 store.go，DDL 字面量里的缩进从两格变成制表符，
// 三份文件当场和代码对不上，而整套测试全绿（它比对的是列集合，不是文本）。一份"事实来源"
// 的导出件悄悄过期，比没有导出件更坏：DBA 照着它建了表，服务起来却想要另一种形状。
//
// 查的是正文（第一条 CREATE 起到文件末尾）必须与 `-ddl <方言>` 的输出逐字节相同；上面那段
// 说明性注释不参与比对，由 migrations/regenerate.sh 保留。
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// migrations 目录在镜像构建上下文之外（.dockerignore 只放 server/ 进去），所以在那一侧跑
// go test 时这些文件不存在。缺文件不是"通过了"，也不是"失败了"，是这一轮没得查 —— 说清楚。
const baselineDir = "../migrations"

func TestBaselineDDLFilesMatchCode(t *testing.T) {
	for _, kind := range []string{"sqlite", "mysql", "postgres"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(baselineDir, "0001-baseline-"+kind+".sql")
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
