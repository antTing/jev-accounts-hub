package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"jevproxy/internal/cryptox"
	"jevproxy/internal/pool"
	"jevproxy/internal/ratelimit"
	"jevproxy/internal/store"
)

func TestValidateSystemOne(t *testing.T) {
	if err := validateSystemOne([]byte(`{"foo":1}`)); err == nil {
		t.Fatal("expected missing fields")
	}
	if err := validateSystemOne([]byte(`{"state":"x","questions":{}}`)); err != nil {
		t.Fatal(err)
	}
}

func TestParseUsage(t *testing.T) {
	in, out, model := parseUsage([]byte(`{"model":"jev-1.13.0","usage":{"input_tokens":12,"output_tokens":3}}`))
	if in != 12 || out != 3 || model != "jev-1.13.0" {
		t.Fatalf("got %d %d %s", in, out, model)
	}
}

func TestGatewayForwardAndBill(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer jev_upstream_secret" {
			t.Errorf("upstream auth %q", got)
		}
		if r.URL.Path != "/v1/systemone" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"model":"jev-1.13.0","answers":{"ok":{"noul":1.0}},"usage":{"input_tokens":42,"output_tokens":1}}`)
	}))
	defer up.Close()

	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	master, _ := cryptox.RandomKey32()
	box, _ := cryptox.NewAESGCM(master)
	enc, err := box.Encrypt([]byte("jev_upstream_secret"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = st.InsertUpstream(context.Background(), store.Upstream{
		Name: "u1", KeyEnc: enc, KeyPrefix: "jev_", KeyLast4: "cret", Weight: 1, RPMLimit: 1000, Status: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	plain := "sk-jev-" + strings.Repeat("a", 40)
	_, err = st.InsertUserKey(context.Background(), store.UserKey{
		Name: "user", KeyHash: cryptox.HashAPIKey(plain), KeyPrefix: "sk-jev-", KeyLast4: "aaaa",
		RPMLimit: 60, TokenQuota: 1000, Status: "active",
	})
	if err != nil {
		t.Fatal(err)
	}

	gw := New(st, pool.New(st, box), ratelimit.New(), up.URL, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodPost, "/v1/systemone", bytes.NewBufferString(`{"state":"hi","model":"jev-latest","questions":{"ok":{"type":"noul","instructions":"x"}}}`))
	req.Header.Set("Authorization", "Bearer "+plain)
	user, err := gw.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	gw.SystemOne(rec, req, user, "rid")
	if rec.Code != 200 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	k, err := st.LookupUserKey(context.Background(), cryptox.HashAPIKey(plain))
	if err != nil {
		t.Fatal(err)
	}
	if k.TokensUsed != 42 {
		t.Fatalf("tokens used %d", k.TokensUsed)
	}
	_ = filepath.Join(dir, "jevproxy.db")
}

func TestRetryOn429(t *testing.T) {
	var n int
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		auth := r.Header.Get("Authorization")
		if strings.Contains(auth, "bad") {
			w.WriteHeader(429)
			_, _ = io.WriteString(w, `{"error":"rate"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"model":"jev-1.13.0","answers":{},"usage":{"input_tokens":7,"output_tokens":0}}`)
	}))
	defer up.Close()

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	master, _ := cryptox.RandomKey32()
	box, _ := cryptox.NewAESGCM(master)
	enc1, _ := box.Encrypt([]byte("jev_bad"))
	enc2, _ := box.Encrypt([]byte("jev_good"))
	_, _ = st.InsertUpstream(context.Background(), store.Upstream{Name: "bad", KeyEnc: enc1, KeyPrefix: "jev_", KeyLast4: "badx", Weight: 1, RPMLimit: 1000, Status: "active"})
	_, _ = st.InsertUpstream(context.Background(), store.Upstream{Name: "good", KeyEnc: enc2, KeyPrefix: "jev_", KeyLast4: "good", Weight: 1, RPMLimit: 1000, Status: "active"})
	plain := "sk-jev-" + strings.Repeat("b", 40)
	_, _ = st.InsertUserKey(context.Background(), store.UserKey{Name: "u", KeyHash: cryptox.HashAPIKey(plain), KeyPrefix: "sk-jev-", KeyLast4: "bbbb", RPMLimit: 60, Status: "active"})

	gw := New(st, pool.New(st, box), ratelimit.New(), up.URL, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodPost, "/v1/systemone", bytes.NewBufferString(`{"state":"hi","questions":{"ok":{"type":"noul","instructions":"x"}}}`))
	req.Header.Set("Authorization", "Bearer "+plain)
	user, err := gw.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	gw.SystemOne(rec, req, user, "rid")
	if rec.Code != 200 {
		t.Fatalf("status %d body %s hits %d", rec.Code, rec.Body.String(), n)
	}
	if n < 1 {
		t.Fatal("expected upstream hit")
	}
}

func TestModelsCatalogPassthrough(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/models" {
			t.Errorf("path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"models":[{"name":"jev-latest","description":"alias","release_date":"2026-09-15"}]}`)
	}))
	defer up.Close()

	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	master, _ := cryptox.RandomKey32()
	box, _ := cryptox.NewAESGCM(master)
	enc, _ := box.Encrypt([]byte("jev_good"))
	_, _ = st.InsertUpstream(context.Background(), store.Upstream{Name: "u", KeyEnc: enc, KeyPrefix: "jev_", KeyLast4: "good", Weight: 1, RPMLimit: 1000, Status: "active"})
	plain := "sk-jev-" + strings.Repeat("c", 40)
	_, _ = st.InsertUserKey(context.Background(), store.UserKey{Name: "u", KeyHash: cryptox.HashAPIKey(plain), KeyPrefix: "sk-jev-", KeyLast4: "cccc", RPMLimit: 60, Status: "active"})

	gw := New(st, pool.New(st, box), ratelimit.New(), up.URL, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	req.Header.Set("Authorization", "Bearer "+plain)
	user, err := gw.Authenticate(req)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	gw.Models(rec, req, user, "rid")
	if rec.Code != 200 {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var cat struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cat); err != nil {
		t.Fatal(err)
	}
	if len(cat.Models) != 1 || cat.Models[0].Name != "jev-latest" {
		t.Fatalf("catalog %+v", cat)
	}
}
