package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// The admin console is compiled into the binary so a deployment is one file plus one DSN.
//
//go:embed all:webdist
var webdist embed.FS

// version 由构建时 -ldflags "-X main.version=v1.2.3" 注入；容器镜像里那一行日志和 /api/healthz
// 都报它，运维不必进容器翻二进制就能确认线上跑的是哪一版。
var version = "dev"

// envOr 让部署方用环境变量注入，而不必去改容器的启动命令：命令行参数照样赢（本机开发、
// 临时试一条 DSN 时手打的更算数）。
func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func main() {
	listen := flag.String("listen", envOr("SYNCD_LISTEN", "127.0.0.1:8791"),
		"监听地址（env SYNCD_LISTEN）；公网部署请放在反代/TLS 后面")
	dsn := flag.String("dsn", envOr("SYNCD_DSN", "sqlite://dropterm-sync.db"),
		"sqlite://路径 | mysql://… | postgres://…（env SYNCD_DSN）")
	ddl := flag.String("ddl", "", "只打印这一方言的建表语句（sqlite|mysql|postgres）然后退出：给 DBA 复核用")
	flag.Parse()

	if *ddl != "" {
		statements, err := ddlFor(*ddl)
		if err != nil {
			log.Fatalf("%v", err)
		}
		for _, q := range statements {
			fmt.Fprintln(os.Stdout, q+";")
		}
		return
	}

	store, err := Open(*dsn)
	if err != nil {
		log.Fatalf("启动失败：%v", err)
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// 先报一句库现在长什么样：线上那一档是 DBA 把表建好的，运维要看得见"这次启动没动表结构"，
	// 而不是事后靠 42501 报错反推。
	if missing := store.missingTables(); len(missing) == 0 {
		log.Printf("库里的表已齐（方言 %s），本次启动不发建表语句", store.kind)
	} else {
		log.Printf("库里缺 %d 张表（%v），本次启动要建", len(missing), missing)
	}
	if err := store.Migrate(ctx); err != nil {
		log.Fatalf("迁移失败：%v", err)
	}

	api := NewServer(store)
	api.openSignup = envOr("SYNCD_OPEN_SIGNUP", "1") != "0"
	// 管理账号只在这台机器第一次起来时按环境变量建。已经存在同名账号就一个字都不动 ——
	// 否则页面上改过的口令会被一次重启悄悄换回环境变量里那一串，而且没人告警。
	if name := strings.ToLower(envOr("SYNCD_ADMIN_USER", "")); name != "" {
		note, err := ensureAdmin(ctx, store, name, os.Getenv("SYNCD_ADMIN_PASSWORD"))
		if err != nil {
			log.Fatalf("管理账号没建起来：%v", err)
		}
		if note != "" {
			log.Printf("%s", note)
		}
	}
	// 通道层（加密传输）不再从命令行开：它按账号在管理页面上配，改完立刻生效，不必重启。
	// 这里只报后端方言，页面才是那把口令的唯一入口。
	mode := "只存密文信封；加密传输在管理页面按账号开启"
	server := &http.Server{
		Addr:              *listen,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// Envelopes are up to 8 MiB, so the read budget has to cover a slow upload without
		// letting a client hold a connection open forever.
		ReadTimeout:  2 * time.Minute,
		WriteTimeout: 2 * time.Minute,
	}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	log.Printf("Yank 同步服务已启动：http://%s （方言 %s，%s）", *listen, store.kind, mode)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("监听失败：%v", err)
	}
}

// ensureAdmin 只在账号不存在时建号，口令走与页面注册同一套 argon2id（含最短长度那道闸）。
// 返回给用户看的那一句；已经有这个账号就返回空串，表示"什么都没动"。
func ensureAdmin(ctx context.Context, store *Store, name, password string) (string, error) {
	if !validUserName(name) {
		return "", fmt.Errorf("SYNCD_ADMIN_USER=%q 不合格：账号需 3–64 个字符，不能含空格", name)
	}
	_, _, err := store.UserByName(ctx, name)
	if err == nil {
		return "", nil
	}
	if !errors.Is(err, ErrNotFound) {
		return "", err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return "", fmt.Errorf("SYNCD_ADMIN_PASSWORD 不合格（%v）；账号 %s 还没建起来", err, name)
	}
	if err := store.CreateUser(ctx, randomID(16), name, hash, time.Now().UTC()); err != nil {
		return "", err
	}
	// 口令本身一个字都不进日志：这一行会进容器日志，而容器日志的可见面比这个服务大得多。
	return fmt.Sprintf("已按环境变量建出管理账号 %s；以后要改口令请在管理页面改，重启不会再动它", name), nil
}

// staticHandler serves the embedded console. Unknown paths fall back to index.html because the
// Vue app routes client-side.
func staticHandler() http.Handler {
	sub, err := fs.Sub(webdist, "webdist")
	if err != nil {
		return http.NotFoundHandler()
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fs.Stat(sub, r.URL.Path[1:]); err != nil {
			r2 := http.Request{Method: "GET", URL: r.URL, Header: r.Header}
			r2.URL.Path = "/"
			fileServer.ServeHTTP(w, &r2)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
