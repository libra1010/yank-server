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
go test ./... || exit 1
echo "syncd green"
