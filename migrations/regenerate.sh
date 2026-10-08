#!/bin/sh
# 重新导出 migrations/{mysql,postgres}.sql —— 全量建表语句，只有这两份。
#
# 为什么要有这个脚本：那两份文件顶着"这是导出的、不是手抄的"的名头，而导出命令
# （go run . -ddl <方言>）只打印 SQL、不含文件顶上那段给 DBA 看的说明。所以"重定向覆盖"
# 这个说法是不可执行的 —— 照着敲一遍，头注就没了，人于是会改成手抄，那份文件从此可能悄悄
# 过期。2026-10-06 换 GORM 重写 store.go 时字面量缩进从两格变成制表符，导出件当场和代码
# 对不上而所有门都绿，就是这个账。
#
# 口径（用户 2026-10-08 拍的）：只出**全量**，不出 0001/0002 那种按版本递增的增量；
# sqlite 是内嵌库、服务自己建，不交付 DDL。老库补列由 Migrate() 启动时探测，不靠人跑 SQL。
#
# 正文 = `go run . -ddl <方言>` 的输出，逐字节；头注由下面这段生成，两边都别手改。
# 对不上的话 server/ddl_parity_test.go 会红，不用再靠人记得跑。
set -eu
cd "$(dirname "$0")/../server"

header() {
    cat <<EOF
-- Yank syncd · 全量建表语句（$1）
--
-- 这一份是**导出的**，不是事实来源：事实来源是 server/store.go 里的 schemaStatements("$2")。
-- 重新导出：sh migrations/regenerate.sh（只打印，不碰任何数据库）。逐字对不上由
-- server/ddl_parity_test.go 判红，不靠人记着跑。
--
-- 什么时候真要手工跑它：只有"连库账号被禁止建表"的生产库 —— DBA 先审这一份、自己建。
-- 正常升级路径不需要：服务启动时 Migrate() 自己 CREATE TABLE IF NOT EXISTS，
-- 老库缺的那几列（auth_kind / notes / jump）也是它探测着补，所以这里没有按版本递增的增量脚本。
--
-- 审表时可以顺手确认的边界（口令与私钥在任何一列都不该出现）：
--   · hosts.auth_kind 存判别名（password / keyboard-interactive / private-key / agent），
--     不是登录账号名，也不是私钥路径 —— 那两个字段服务端读完即丢；
--   · hosts.notes 与 snippets.body 是端侧嗅探过的内容，命中疑似口令的那条在离机前就被整句替换；
--   · blobs.payload 与历史版本是端到端信封密文，服务端不解析、不落列、任何 GET 都不回吐；
--   · settings 里那一格通道口令是**原文**存的（外层只挡"读得清主机地址，读不出 SSH 口令"），
--     所以库文件本身要当凭据级资产对待 —— 这句必须写在交付说明里，不是吓人的。
EOF
}

for kind in mysql postgres; do
    file="../migrations/$kind.sql"
    case "$kind" in
        mysql) title="MySQL 8" ;;
        postgres) title="PostgreSQL" ;;
    esac
    header "$title" "$kind" > "/tmp/syncd-ddl-$kind.sql"
    # 先导到临时件、成功才换正式件。踩过一次：go 不在 PATH 里时 `go run` 失败，而
    # "> $file" 早把交付件截成只剩头注 —— 导出失败不许顺手毁掉上一份好文件。
    go run . -ddl "$kind" >> "/tmp/syncd-ddl-$kind.sql"
    mv "/tmp/syncd-ddl-$kind.sql" "$file"
    echo "$kind：全量正文已从代码导出（$(grep -c '^CREATE' "$file") 条 CREATE/索引语句，$(wc -l < "$file") 行）"
done
