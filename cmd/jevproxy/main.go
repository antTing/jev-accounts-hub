package main

import (
	"context"
	"encoding/hex"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"jevproxy/internal/config"
	"jevproxy/internal/cryptox"
	"jevproxy/internal/httpserver"
	"jevproxy/internal/pool"
	"jevproxy/internal/proxy"
	"jevproxy/internal/ratelimit"
	"jevproxy/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		slog.Error("data dir", "err", err)
		os.Exit(1)
	}

	log := newLogger(cfg.LogFormat, cfg.Debug)

	adminToken, err := loadOrCreate(filepath.Join(cfg.DataDir, "admin.token"), cfg.AdminToken, randomToken)
	if err != nil {
		log.Error("admin token", "err", err)
		os.Exit(1)
	}
	cfg.AdminToken = adminToken

	masterHex, err := loadOrCreate(filepath.Join(cfg.DataDir, "master.key"), cfg.MasterKey, randomMaster)
	if err != nil {
		log.Error("master key", "err", err)
		os.Exit(1)
	}
	key, err := cryptox.ParseMasterKey(strings.TrimSpace(masterHex))
	if err != nil {
		log.Error("parse master key", "err", err)
		os.Exit(1)
	}
	box, err := cryptox.NewAESGCM(key)
	if err != nil {
		log.Error("aes", "err", err)
		os.Exit(1)
	}

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Error("store", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	p := pool.New(st, box)
	lim := ratelimit.New()
	gw := proxy.New(st, p, lim, cfg.Upstream, cfg.Timeout, log)
	srv := httpserver.New(httpserver.Config{
		Listen:     cfg.Listen,
		AdminToken: cfg.AdminToken,
		Debug:      cfg.Debug,
	}, st, box, p, gw, log)

	log.Info("jevproxy starting",
		"listen", cfg.Listen,
		"data", cfg.DataDir,
		"upstream", cfg.Upstream,
	)
	log.Info("open the admin UI, then paste the token from data/admin.token",
		"ui", "http://127.0.0.1"+uiPort(cfg.Listen),
		"token_file", filepath.Join(cfg.DataDir, "admin.token"),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start() }()

	select {
	case <-ctx.Done():
		shut, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
		log.Info("stopped")
	case err := <-errCh:
		if err != nil {
			log.Error("server", "err", err)
			os.Exit(1)
		}
	}
}

func newLogger(format string, debug bool) *slog.Logger {
	level := slog.LevelInfo
	if debug {
		level = slog.LevelDebug
	}
	opts := &slog.HandlerOptions{Level: level}
	if strings.ToLower(format) == "json" {
		return slog.New(slog.NewJSONHandler(os.Stdout, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

func loadOrCreate(path, provided string, gen func() (string, error)) (string, error) {
	if strings.TrimSpace(provided) != "" {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			_ = cryptox.WriteFile0600(path, strings.TrimSpace(provided)+"\n")
		}
		return strings.TrimSpace(provided), nil
	}
	if b, err := os.ReadFile(path); err == nil {
		v := strings.TrimSpace(string(b))
		if v != "" {
			return v, nil
		}
	}
	v, err := gen()
	if err != nil {
		return "", err
	}
	if err := cryptox.WriteFile0600(path, v+"\n"); err != nil {
		return "", err
	}
	return v, nil
}

func randomToken() (string, error) {
	return cryptox.RandomString(48)
}

func randomMaster() (string, error) {
	b, err := cryptox.RandomKey32()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func uiPort(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return listen
	}
	if listen == "" {
		return ":8080"
	}
	return listen
}
