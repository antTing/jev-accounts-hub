package outproxy

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"jevproxy/internal/store"
)

var allowedSchemes = map[string]bool{
	"http":    true,
	"https":   true,
	"socks5":  true,
	"socks5h": true,
}

// Parse 解析单条代理。空字符串表示直连（返回零值 Proxy 和 nil error 不合适，
// 调用方应自行判断空输入）。非空但无效则 fail-fast。
func Parse(raw string) (store.Proxy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return store.Proxy{}, fmt.Errorf("empty proxy")
	}
	if looksLikeURL(raw) {
		return parseURL(raw)
	}
	return parseHostPort(raw)
}

func looksLikeURL(s string) bool {
	i := strings.Index(s, "://")
	if i <= 0 {
		return false
	}
	scheme := strings.ToLower(s[:i])
	return allowedSchemes[scheme]
}

func parseURL(raw string) (store.Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return store.Proxy{}, fmt.Errorf("invalid proxy URL")
	}
	if u.Host == "" || u.Hostname() == "" {
		return store.Proxy{}, fmt.Errorf("proxy URL missing host")
	}
	scheme := strings.ToLower(u.Scheme)
	if !allowedSchemes[scheme] {
		return store.Proxy{}, fmt.Errorf("unsupported proxy scheme %q", scheme)
	}
	if scheme == "socks5" {
		scheme = "socks5h"
	}
	port, err := portOf(u)
	if err != nil {
		return store.Proxy{}, err
	}
	user, pass := "", ""
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	return store.Proxy{
		Name:     defaultName(u.Hostname(), port),
		Protocol: scheme,
		Host:     u.Hostname(),
		Port:     port,
		Username: user,
		Password: pass,
		Status:   "active",
	}, nil
}

func portOf(u *url.URL) (int, error) {
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return 0, fmt.Errorf("invalid proxy port")
		}
		return n, nil
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return 80, nil
	case "https":
		return 443, nil
	default:
		return 0, fmt.Errorf("proxy URL missing port")
	}
}

// parseHostPort 接受 host:port、host:port:user:pass、user:pass@host:port。
func parseHostPort(raw string) (store.Proxy, error) {
	raw = strings.TrimSpace(raw)
	host, port, user, pass := "", 0, "", ""

	if at := strings.LastIndex(raw, "@"); at >= 0 {
		cred, rest := raw[:at], raw[at+1:]
		h, p, err := splitHostPort(rest)
		if err != nil {
			return store.Proxy{}, err
		}
		host, port = h, p
		if i := strings.Index(cred, ":"); i >= 0 {
			user, pass = cred[:i], cred[i+1:]
		} else {
			user = cred
		}
	} else {
		parts := strings.Split(raw, ":")
		switch len(parts) {
		case 2:
			h, p, err := splitHostPort(raw)
			if err != nil {
				return store.Proxy{}, err
			}
			host, port = h, p
		case 4:
			h, p, err := splitHostPort(parts[0] + ":" + parts[1])
			if err != nil {
				return store.Proxy{}, err
			}
			host, port = h, p
			user, pass = parts[2], parts[3]
		default:
			return store.Proxy{}, fmt.Errorf("invalid proxy address")
		}
	}

	return store.Proxy{
		Name:     defaultName(host, port),
		Protocol: "http",
		Host:     host,
		Port:     port,
		Username: user,
		Password: pass,
		Status:   "active",
	}, nil
}

func splitHostPort(s string) (string, int, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, fmt.Errorf("invalid proxy address")
	}
	if h == "" {
		return "", 0, fmt.Errorf("proxy missing host")
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return "", 0, fmt.Errorf("invalid proxy port")
	}
	return h, n, nil
}

func defaultName(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// ParseLine 解析批量导入的一行。支持可选名称前缀：`us-1 socks5://host:1080`。
func ParseLine(line string) (store.Proxy, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return store.Proxy{}, fmt.Errorf("empty proxy")
	}
	if looksLikeURL(line) || strings.Contains(line, "@") {
		p, err := Parse(line)
		if err != nil {
			return store.Proxy{}, err
		}
		return p, nil
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return store.Proxy{}, fmt.Errorf("empty proxy")
	}
	if len(fields) == 1 {
		return Parse(fields[0])
	}
	rest := strings.Join(fields[1:], " ")
	if looksLikeURL(rest) || strings.Count(rest, ":") >= 1 {
		p, err := Parse(rest)
		if err != nil {
			return Parse(line)
		}
		name := strings.TrimSpace(fields[0])
		if name != "" && !strings.Contains(name, ":") && !strings.Contains(name, "/") {
			p.Name = name
		}
		return p, nil
	}
	return Parse(line)
}

func URL(p store.Proxy) string {
	u := &url.URL{
		Scheme: p.Protocol,
		Host:   net.JoinHostPort(p.Host, strconv.Itoa(p.Port)),
	}
	if p.Username != "" {
		if p.Password != "" {
			u.User = url.UserPassword(p.Username, p.Password)
		} else {
			u.User = url.User(p.Username)
		}
	}
	return u.String()
}

func Redacted(p store.Proxy) string {
	u := &url.URL{
		Scheme: p.Protocol,
		Host:   net.JoinHostPort(p.Host, strconv.Itoa(p.Port)),
	}
	if p.Username != "" {
		u.User = url.UserPassword(p.Username, "****")
	}
	return u.String()
}

func Normalize(p *store.Proxy) error {
	p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
	p.Host = strings.TrimSpace(p.Host)
	p.Username = strings.TrimSpace(p.Username)
	p.Name = strings.TrimSpace(p.Name)
	if p.Protocol == "socks5" {
		p.Protocol = "socks5h"
	}
	if !allowedSchemes[p.Protocol] {
		return fmt.Errorf("unsupported proxy scheme %q", p.Protocol)
	}
	if p.Host == "" {
		return fmt.Errorf("proxy missing host")
	}
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("invalid proxy port")
	}
	if p.Name == "" {
		p.Name = defaultName(p.Host, p.Port)
	}
	if p.Status == "" {
		p.Status = "active"
	}
	return nil
}
