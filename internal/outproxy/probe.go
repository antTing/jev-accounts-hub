package outproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"jevproxy/internal/store"
)

const maxProbeBody = 1 << 20

type ProbeResult struct {
	OK        bool
	LatencyMS int64
	IP        string
	Country   string
	Error     string
}

func Probe(ctx context.Context, p store.Proxy, timeout time.Duration) ProbeResult {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	cli, err := NewClient(timeout, &p)
	if err != nil {
		return ProbeResult{Error: err.Error()}
	}
	type target struct {
		url    string
		parser string
	}
	targets := []target{
		{"http://ip-api.com/json/?fields=status,message,query,country,countryCode", "ip-api"},
		{"http://httpbin.org/ip", "httpbin"},
	}
	var last error
	for _, t := range targets {
		res, err := probeOne(ctx, cli, t.url, t.parser)
		if err == nil {
			return res
		}
		last = err
	}
	msg := "all probe URLs failed"
	if last != nil {
		msg = last.Error()
	}
	return ProbeResult{Error: msg}
}

func probeOne(ctx context.Context, cli *http.Client, rawURL, parser string) (ProbeResult, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ProbeResult{}, err
	}
	resp, err := cli.Do(req)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return ProbeResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody+1))
	if err != nil {
		return ProbeResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return ProbeResult{}, fmt.Errorf("probe http %d", resp.StatusCode)
	}
	switch parser {
	case "ip-api":
		var info struct {
			Status  string `json:"status"`
			Message string `json:"message"`
			Query   string `json:"query"`
			Country string `json:"country"`
		}
		if err := json.Unmarshal(body, &info); err != nil {
			return ProbeResult{}, fmt.Errorf("parse ip-api: %w", err)
		}
		if strings.ToLower(info.Status) != "success" {
			msg := info.Message
			if msg == "" {
				msg = "ip-api failed"
			}
			return ProbeResult{}, fmt.Errorf("%s", msg)
		}
		return ProbeResult{OK: true, LatencyMS: lat, IP: info.Query, Country: info.Country}, nil
	case "httpbin":
		var info struct {
			Origin string `json:"origin"`
		}
		if err := json.Unmarshal(body, &info); err != nil {
			return ProbeResult{}, fmt.Errorf("parse httpbin: %w", err)
		}
		if info.Origin == "" {
			return ProbeResult{}, fmt.Errorf("httpbin: empty origin")
		}
		return ProbeResult{OK: true, LatencyMS: lat, IP: info.Origin}, nil
	default:
		return ProbeResult{}, fmt.Errorf("unknown parser")
	}
}
