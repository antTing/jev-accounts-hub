package outproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"jevproxy/internal/store"
)

func TestConfigureTransportHTTP(t *testing.T) {
	tr := &http.Transport{}
	p := &store.Proxy{Protocol: "http", Host: "proxy.example.com", Port: 8080}
	if err := ConfigureTransport(tr, p); err != nil {
		t.Fatal(err)
	}
	if tr.Proxy == nil {
		t.Fatal("http proxy should set Transport.Proxy")
	}
	u, err := tr.Proxy(&http.Request{URL: mustURL("https://api.typesafe.ai/")})
	if err != nil || u == nil || u.Host != "proxy.example.com:8080" {
		t.Fatalf("proxy url %v %v", u, err)
	}
}

func TestConfigureTransportSOCKS(t *testing.T) {
	tr := &http.Transport{}
	p := &store.Proxy{Protocol: "socks5h", Host: "127.0.0.1", Port: 1080}
	if err := ConfigureTransport(tr, p); err != nil {
		t.Fatal(err)
	}
	if tr.Proxy != nil {
		t.Fatal("socks should not set Proxy")
	}
	if tr.DialContext == nil {
		t.Fatal("socks should set DialContext")
	}
}

func TestClientsCacheDirect(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer up.Close()
	c := NewClients(5 * time.Second)
	a, err := c.Get(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Get(nil)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("direct clients should be reused")
	}
	resp, err := a.Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
