package outproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"

	"jevproxy/internal/store"
)

const (
	defaultDialTimeout         = 8 * time.Second
	defaultTLSHandshakeTimeout = 8 * time.Second
	defaultIdleConnTimeout     = 90 * time.Second
)

func parsedURL(p *store.Proxy) (*url.URL, error) {
	if p == nil {
		return nil, nil
	}
	raw := URL(*p)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL")
	}
	return u, nil
}

func ConfigureTransport(t *http.Transport, p *store.Proxy) error {
	if p == nil {
		return nil
	}
	u, err := parsedURL(p)
	if err != nil {
		return err
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "http", "https":
		t.Proxy = http.ProxyURL(u)
		return nil
	case "socks5", "socks5h":
		dialer, err := proxy.FromURL(u, proxy.Direct)
		if err != nil {
			return fmt.Errorf("create socks5 dialer: %w", err)
		}
		if cd, ok := dialer.(proxy.ContextDialer); ok {
			t.DialContext = cd.DialContext
		} else {
			t.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
		}
		return nil
	default:
		return fmt.Errorf("unsupported proxy scheme: %s", scheme)
	}
}

func NewClient(timeout time.Duration, p *store.Proxy) (*http.Client, error) {
	if timeout < time.Second {
		timeout = 15 * time.Second
	}
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: defaultDialTimeout,
		}).DialContext,
		TLSHandshakeTimeout: defaultTLSHandshakeTimeout,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     defaultIdleConnTimeout,
	}
	if err := ConfigureTransport(tr, p); err != nil {
		return nil, err
	}
	return &http.Client{Timeout: timeout, Transport: tr}, nil
}

type Clients struct {
	timeout time.Duration
	mu      sync.Mutex
	m       map[string]*http.Client
}

func NewClients(timeout time.Duration) *Clients {
	if timeout < time.Second {
		timeout = 15 * time.Second
	}
	return &Clients{timeout: timeout, m: map[string]*http.Client{}}
}

func (c *Clients) Get(p *store.Proxy) (*http.Client, error) {
	key := "direct"
	if p != nil {
		key = URL(*p)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if cli, ok := c.m[key]; ok {
		return cli, nil
	}
	cli, err := NewClient(c.timeout, p)
	if err != nil {
		return nil, err
	}
	c.m[key] = cli
	return cli, nil
}
