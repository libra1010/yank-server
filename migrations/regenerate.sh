#!/bin/sh
# 重新生成 0001-baseline-<方言>.sql 的**正文**。
#
# 为什么要有这个脚本：那三份文件顶着"这是导出的、不是手抄的"的名头，而导出命令
# （go run . -ddl <方言>）只打印 SQL、不含文件顶上那段给 DBA 看的说明。所以"重定向覆盖"
# 这个说法是不可执行的 —— 照着敲一遍，头注就没了，人于是会改成手抄，那份文件从此可能悄悄
# 过期。2026-10-06 换 GORM 重写 store.go 时字面量缩进从两格变成制表符，三份文件当场和代码
# 对不上而所有门都绿，就是这个账。
#
# 现在：正文 = 那一条命令的输出，逐字节；头注 = 第一条 CREATE 之前的那几行，原样保留。
# 对不上的话 ddl_parity_test.go 会红，不用再靠人记得跑。
set -eu
cd "$(dirname "$0")/../server"
for kind in sqlite mysql postgres; do
    file="../migrations/0001-baseline-$kind.sql"
    go run . -ddl "$kind" > "/tmp/syncd-ddl-$kind.sql"
    awk '/^CREATE TABLE/{exit} {print}' "$file" > "/tmp/syncd-ddl-$kind.hdr"
    cat "/tmp/syncd-ddl-$kind.hdr" "/tmp/syncd-ddl-$kind.sql" > "$file"
    echo "$kind：正文已从代码导出（$(grep -c '^CREATE' "$file") 条 CREATE/索引语句）"
done
