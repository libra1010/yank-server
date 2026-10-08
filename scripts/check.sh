#!/bin/bash
# Gate for the Go sync service: formatting, vet, unit + interop tests.
#
# The interop test reads syncd/testdata/envelope-vectors.json, which the Swift gate emits with
# DT_EMIT_VECTORS=1 — so this script only proves the server matches the client as long as the
# vectors are regenerated whenever the envelope format changes.
set -u
export GOROOT="${GOROOT:-/opt/soft-opt/sdk/go/go1.27.1}"
export PATH="$GOROOT/bin:$PATH"
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
export GOFLAGS="-mod=mod"
cd "$(dirname "$0")/../server" || exit 1

if ! command -v go >/dev/null 2>&1; then
    echo "找不到 go 工具链（GOROOT=$GOROOT）"
    exit 1
fi

# gofmt prints syntax errors to stderr and still exits non-zero; judging only by empty stdout
# would call a broken file "clean".
UNFORMATTED=$(gofmt -l -e . 2>/tmp/dt-syncd-gofmt.log)
GOFMT_STATUS=$?
if [ $GOFMT_STATUS -ne 0 ]; then
    echo "gofmt 解析失败："; cat /tmp/dt-syncd-gofmt.log; exit 1
fi
if [ -n "$UNFORMATTED" ]; then
    echo "gofmt 未通过：$UNFORMATTED"; exit 1
fi

go vet ./... || exit 1

# 两份 Dockerfile 只对账"指令"那一部分：一份走官方源、一份走国内加速地址，除了基础镜像的
# 地址和 GOPROXY 的默认值，别的都不许分叉。改一边忘一边是最坏的那种漂 —— 两边都能 build，
# 只是其中一张网上不去。
# 这里已经在 server/ 里了，所以根目录只能从 cwd 往上走一层；早先写相对 dirname 取空过，
# 结果 sed 读不到文件、diff 比了两个空串，门照样绿 —— 文件不在必须当场炸，不许往下比。
ROOT="$(cd .. && pwd)"
for f in "$ROOT/Dockerfile" "$ROOT/Dockerfile.cn"; do
    [ -s "$f" ] || { echo "读不到 $f：漂移门没法比，直接算失败"; exit 1; }
done
norm() { sed -e '/^[[:space:]]*#/d' -e '/^ARG MIRROR/d' -e '/^ARG GOPROXY/d' \
             -e 's|\${MIRROR}/||g' "$1"; }
if ! diff -u <(norm "$ROOT/Dockerfile") <(norm "$ROOT/Dockerfile.cn") \
        > /tmp/dt-dockerfile-drift.diff; then
    echo "两份 Dockerfile 的指令部分漂了（去掉源地址与 GOPROXY 后仍不同）："
    cat /tmp/dt-dockerfile-drift.diff
    exit 1
fi

go test ./... || exit 1
echo "syncd green"
