package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config 进程配置，全部来自环境变量。
type Config struct {
	Listen     string
	DataDir    string
	AdminToken string
	MasterKey  string // 64 hex chars；空则启动时生成
	Upstream   string
	Timeout    time.Duration
	LogFormat  string
	Debug      bool
}

func Load() (Config, error) {
	c := Config{
		Listen:    env("JEVPROXY_LISTEN", ":8080"),
		DataDir:   env("JEVPROXY_DATA_DIR", "./data"),
		AdminToken: strings.TrimSpace(os.Getenv("JEVPROXY_ADMIN_TOKEN")),
		MasterKey:  strings.TrimSpace(os.Getenv("JEVPROXY_MASTER_KEY")),
		Upstream:  strings.TrimRight(env("JEVPROXY_UPSTREAM", "https://api.typesafe.ai"), "/"),
		LogFormat: env("JEVPROXY_LOG_FORMAT", "text"),
		Debug:     env("JEVPROXY_DEBUG", "0") == "1",
	}
	to := env("JEVPROXY_TIMEOUT", "15s")
	d, err := time.ParseDuration(to)
	if err != nil {
		sec, convErr := strconv.Atoi(to)
		if convErr != nil {
			return c, fmt.Errorf("JEVPROXY_TIMEOUT: %w", err)
		}
		d = time.Duration(sec) * time.Second
	}
	if d < time.Second {
		d = 15 * time.Second
	}
	c.Timeout = d
	return c, nil
}

func env(k, def string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	return v
}
