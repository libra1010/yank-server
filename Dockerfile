# syntax=docker/dockerfile:1
# Yank 同步服务（syncd）：开源发布用的服务端镜像。
#
# 两阶段构建的理由：管理端（Vue）已经用 go:embed 打进 server/webdist，容器里根本不需要
# Node —— 构建层只要有 Go，运行层只要一个能跑 healthcheck 的 alpine。
# 产物是纯静态二进制（CGO_ENABLED=0；GORM 那三个方言驱动都是纯 Go —— sqlite 走 glebarez
# 这套、内核是 modernc，mysql/pgsql 走 go-sql-driver 与 pgx），所以运行层不装 libc 之外的
# 任何东西，也不带编译器。
#
# 国内拉基础镜像：默认走 DaoCloud 的公共加速地址。换源不必改这份文件：
#   docker build --build-arg MIRROR=registry.cn-hangzhou.aliyuncs.com/library ...
# 留空就回到官方 Docker Hub（~/.docker/daemon.json 里配了 registry-mirrors 的话也照样生效）：
#   docker build --build-arg MIRROR= ...
# Go 模块默认走 goproxy.cn，同理可用 --build-arg GOPROXY= 覆盖。

ARG MIRROR=docker.m.daocloud.io/library
ARG GO_VERSION=1.27
ARG ALPINE_VERSION=3.22

FROM ${MIRROR}/golang:${GO_VERSION}-alpine AS build

ARG GOPROXY=https://goproxy.cn,direct
ENV GOPROXY=${GOPROXY} \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOFLAGS=-trimpath

WORKDIR /src

# 先只喂 go.mod/go.sum：依赖没变时这一层直接吃缓存，改一行业务代码不必重下模块。
COPY server/go.mod server/go.sum ./
RUN go mod download && go mod verify

COPY server/ ./
ARG VERSION=dev
RUN go build -ldflags "-s -w -X main.version=${VERSION}" -o /out/syncd .

# 构建层就把测试跑一遍：门禁红在这里，比部署到机器上再红便宜得多。
RUN go test ./...

FROM ${MIRROR}/alpine:${ALPINE_VERSION} AS runtime

# 不用 root 跑：这个服务对外收 HTTP，镜像里也没有任何需要 root 的事。
# uid 固定成 10001 —— 换成 bind mount 挂 /data 时，宿主机那一侧要 chown 的就是这个数字，
# 写在镜像里比写在文档里更不容易漂。
RUN adduser -D -u 10001 -h /data syncd

COPY --from=build /out/syncd /usr/local/bin/syncd

# 容器里监听 0.0.0.0：它本来就躲在反代或宿主端口映射后面，绑 127.0.0.1 会让端口映射失效。
# 数据库落在 /data 这个卷上，重建容器不会把清单一起重建掉。
# 口令类的环境变量（SYNCD_ADMIN_PASSWORD、通道密钥）一个都不写在这里 —— 镜像是要公开的。
ENV SYNCD_LISTEN=0.0.0.0:8791 \
    SYNCD_DSN=sqlite:///data/dropterm-sync.db

VOLUME /data
EXPOSE 8791
USER syncd

# 探针打的就是 /api/healthz（它回 {"ok":true,"dialect":…,"version":…,"openSignup":…}）。
# 只 grep ok 不 grep 版本串：升级换版本号不该让一个健康运行的容器变成 unhealthy。
HEALTHCHECK --interval=30s --timeout=3s --start-period=8s --retries=3 \
    CMD wget -qO- "http://127.0.0.1:8791/api/healthz" | grep -q '"ok":true' || exit 1

ENTRYPOINT ["/usr/local/bin/syncd"]
