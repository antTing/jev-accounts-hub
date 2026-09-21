package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"jevproxy/internal/cryptox"
	"jevproxy/internal/outproxy"
	"jevproxy/internal/pool"
	"jevproxy/internal/ratelimit"
	"jevproxy/internal/store"
)

const maxBody = 8 << 20 // 8 MiB

type Gateway struct {
	Store    *store.Store
	Pool     *pool.Pool
	Limit    *ratelimit.Limiter
	Picker   *outproxy.Picker
	Clients  *outproxy.Clients
	Upstream string
	Timeout  time.Duration
	Client   *http.Client
	Log      *slog.Logger

	modelsMu    sync.Mutex
	modelsBody  []byte
	modelsUntil time.Time
}

func New(st *store.Store, p *pool.Pool, lim *ratelimit.Limiter, upstream string, timeout time.Duration, log *slog.Logger) *Gateway {
	if timeout < time.Second {
		timeout = 15 * time.Second
	}
	direct, _ := outproxy.NewClient(timeout, nil)
	return &Gateway{
		Store:    st,
		Pool:     p,
		Limit:    lim,
		Picker:   outproxy.NewPicker(st),
		Clients:  outproxy.NewClients(timeout),
		Upstream: strings.TrimRight(upstream, "/"),
		Timeout:  timeout,
		Client:   direct,
		Log:      log,
	}
}

type usage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
}

type upstreamResp struct {
	Model string `json:"model"`
	Usage usage  `json:"usage"`
}

func (g *Gateway) Authenticate(r *http.Request) (store.UserKey, error) {
	raw := r.Header.Get("Authorization")
	if !strings.HasPrefix(raw, "Bearer ") {
		return store.UserKey{}, errHTTP(401, "invalid_api_key", "missing bearer token")
	}
	plain := strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
	if !strings.HasPrefix(plain, "sk-jev-") || len(plain) < 20 {
		return store.UserKey{}, errHTTP(401, "invalid_api_key", "invalid api key")
	}
	k, err := g.Store.LookupUserKey(r.Context(), cryptox.HashAPIKey(plain))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return store.UserKey{}, errHTTP(401, "invalid_api_key", "invalid api key")
		}
		return store.UserKey{}, errHTTP(500, "internal_error", "lookup failed")
	}
	if !k.Active() {
		return store.UserKey{}, errHTTP(401, "invalid_api_key", "api key disabled or expired")
	}
	if k.TokenQuota > 0 && k.TokensUsed >= k.TokenQuota {
		return store.UserKey{}, errHTTP(402, "quota_exceeded", "token quota exceeded")
	}
	if ok, wait := g.Limit.Allow(fmt.Sprintf("u:%d", k.ID), k.RPMLimit); !ok {
		e := errHTTP(429, "rate_limited", "user rpm limit exceeded")
		e.retryAfter = int(wait.Seconds())
		return store.UserKey{}, e
	}
	return k, nil
}

type EvalResult struct {
	Status       int
	Header       http.Header
	Body         []byte
	LatencyMS    int64
	UpstreamID   *int64
	InputTokens  int64
	OutputTokens int64
	Model        string
	Err          error
}

func (g *Gateway) SystemOne(w http.ResponseWriter, r *http.Request, user store.UserKey, requestID string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		writeErr(w, errHTTP(400, "bad_request", "read body failed"))
		return
	}
	if len(body) > maxBody {
		writeErr(w, errHTTP(413, "payload_too_large", "request body too large"))
		return
	}
	res := g.Evaluate(r.Context(), &user, body, requestID)
	if res.Err != nil && len(res.Body) == 0 {
		writeErr(w, res.Err)
		return
	}
	if res.Header == nil {
		res.Header = http.Header{}
	}
	g.copyUpstream(w, res.Status, res.Header, res.Body)
}

func (g *Gateway) Evaluate(ctx context.Context, user *store.UserKey, body []byte, requestID string) EvalResult {
	if err := validateSystemOne(body); err != nil {
		return EvalResult{Status: 400, Err: err, Body: errorJSON(err)}
	}

	userID := int64(0)
	if user != nil {
		userID = user.ID
	}

	exclude := map[int64]struct{}{}
	proxyExclude := map[int64]struct{}{}
	var last httpErr
	attempts := 3
	for i := 0; i < attempts; i++ {
		sel, err := g.Pool.Pick(ctx, exclude)
		if err != nil {
			if errors.Is(err, pool.ErrNoUpstream) {
				he := errHTTP(503, "no_upstream", "no available upstream key")
				g.logFailID(ctx, userID, nil, "", 0, 503, "no upstream", requestID)
				return EvalResult{Status: 503, Err: he, Body: errorJSON(he)}
			}
			he := errHTTP(500, "internal_error", err.Error())
			return EvalResult{Status: 500, Err: he, Body: errorJSON(he)}
		}
		if ok, wait := g.Limit.Allow(fmt.Sprintf("up:%d", sel.Up.ID), sel.Up.RPMLimit); !ok {
			exclude[sel.Up.ID] = struct{}{}
			last = errHTTP(429, "rate_limited", "upstream rpm limit")
			last.retryAfter = int(wait.Seconds())
			continue
		}

		choice, perr := g.pickExit(ctx, sel.Up, proxyExclude)
		if perr != nil {
			exclude[sel.Up.ID] = struct{}{}
			last = errHTTP(502, "proxy_error", perr.Error())
			g.Log.Warn("proxy pick failed", "upstream_id", sel.Up.ID, "err", perr, "attempt", i+1)
			continue
		}
		status, respBody, hdr, lat, ferr := g.forward(ctx, http.MethodPost, "/v1/systemone", body, sel.APIKey, requestID, choice.Proxy)
		upID := sel.Up.ID
		if ferr != nil {
			g.markProxyTransportErr(ctx, choice, ferr)
			if choice.Proxy != nil {
				proxyExclude[choice.Proxy.ID] = struct{}{}
			}
			g.Pool.MarkErr(ctx, upID, ferr.Error(), 0)
			exclude[upID] = struct{}{}
			last = errHTTP(502, "upstream_error", ferr.Error())
			g.Log.Warn("upstream transport error", "upstream_id", upID, "err", ferr, "attempt", i+1)
			continue
		}

		g.markProxyOK(ctx, choice, lat)
		retryable := status == 429 || status == 529 || status >= 500
		authFail := status == 401 || status == 403
		if retryable || authFail {
			msg := snippet(respBody)
			g.Pool.MarkErr(ctx, upID, fmt.Sprintf("http %d %s", status, msg), status)
			exclude[upID] = struct{}{}
			last = errHTTP(status, "upstream_error", fmt.Sprintf("upstream http %d", status))
			if ra := hdr.Get("Retry-After"); ra != "" {
				if n, e := strconv.Atoi(ra); e == nil {
					last.retryAfter = n
				}
			}
			continue
		}

		model := modelOf(body)
		inTok, outTok, parsed := parseUsage(respBody)
		if parsed != "" {
			model = parsed
		}
		ok := status >= 200 && status < 300
		if ok {
			g.Pool.MarkOK(ctx, upID)
			if user != nil {
				_ = g.Store.AddTokens(ctx, user.ID, inTok)
			}
		}
		_ = g.Store.InsertLog(ctx, store.UsageLog{
			UserKeyID:    userID,
			UpstreamID:   &upID,
			Model:        model,
			InputTokens:  inTok,
			OutputTokens: outTok,
			LatencyMS:    lat,
			StatusCode:   status,
			OK:           ok,
			Error:        ifNotOK(ok, snippet(respBody)),
			RequestID:    requestID,
		})
		return EvalResult{
			Status: status, Header: hdr, Body: respBody, LatencyMS: lat,
			UpstreamID: &upID, InputTokens: inTok, OutputTokens: outTok, Model: model,
		}
	}

	if last.code == 0 {
		last = errHTTP(502, "upstream_error", "all upstream attempts failed")
	}
	g.logFailID(ctx, userID, nil, modelOf(body), 0, last.code, last.msg, requestID)
	return EvalResult{Status: last.code, Err: last, Body: errorJSON(last)}
}

func ifNotOK(ok bool, s string) string {
	if ok {
		return ""
	}
	return s
}

func errorJSON(err error) []byte {
	he, ok := IsHTTPErr(err)
	if !ok {
		he = errHTTP(500, "internal_error", err.Error())
	}
	b, _ := json.Marshal(map[string]any{"error": map[string]any{"type": he.kind, "message": he.msg}})
	return append(b, '\n')
}

func catalogFallback() map[string]any {
	return map[string]any{
		"models": []map[string]any{
			{"name": "jev-latest", "description": "Stable alias; currently jev-1.13.0", "release_date": "2026-09-15"},
			{"name": "jev-preview", "description": "Newest alias; currently jev-1.13.0", "release_date": "2026-09-15"},
			{"name": "jev-1.13.0", "description": "Jev 1.13 System One", "release_date": "2026-09-15"},
		},
	}
}

func (g *Gateway) Models(w http.ResponseWriter, r *http.Request, user store.UserKey, requestID string) {
	if cached := g.cachedModels(); cached != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(cached)
		return
	}

	exclude := map[int64]struct{}{}
	proxyExclude := map[int64]struct{}{}
	for i := 0; i < 3; i++ {
		sel, err := g.Pool.Pick(r.Context(), exclude)
		if err != nil {
			if errors.Is(err, pool.ErrNoUpstream) {
				writeJSON(w, 200, catalogFallback())
				return
			}
			writeErr(w, errHTTP(500, "internal_error", err.Error()))
			return
		}
		choice, perr := g.pickExit(r.Context(), sel.Up, proxyExclude)
		if perr != nil {
			exclude[sel.Up.ID] = struct{}{}
			continue
		}
		status, respBody, hdr, lat, ferr := g.forward(r.Context(), http.MethodGet, "/v1/models", nil, sel.APIKey, requestID, choice.Proxy)
		upID := sel.Up.ID
		if ferr != nil || status == 429 || status == 529 || status >= 500 || status == 401 || status == 403 {
			msg := ""
			if ferr != nil {
				msg = ferr.Error()
				g.markProxyTransportErr(r.Context(), choice, ferr)
				if choice.Proxy != nil {
					proxyExclude[choice.Proxy.ID] = struct{}{}
				}
			} else {
				msg = snippet(respBody)
				g.markProxyOK(r.Context(), choice, lat)
			}
			code := status
			if ferr != nil {
				code = 0
			}
			g.Pool.MarkErr(r.Context(), upID, msg, code)
			exclude[upID] = struct{}{}
			continue
		}
		g.markProxyOK(r.Context(), choice, lat)
		g.Pool.MarkOK(r.Context(), upID)
		_ = g.Store.InsertLog(r.Context(), store.UsageLog{
			UserKeyID:  user.ID,
			UpstreamID: &upID,
			Model:      "models",
			LatencyMS:  lat,
			StatusCode: status,
			OK:         status >= 200 && status < 300,
			RequestID:  requestID,
		})
		if status >= 200 && status < 300 && looksLikeModelCatalog(respBody) {
			g.rememberModels(respBody)
		}
		g.copyUpstream(w, status, hdr, respBody)
		return
	}
	if cached := g.cachedModels(); cached != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(cached)
		return
	}
	writeJSON(w, 200, catalogFallback())
}

func (g *Gateway) cachedModels() []byte {
	g.modelsMu.Lock()
	defer g.modelsMu.Unlock()
	if len(g.modelsBody) == 0 || time.Now().After(g.modelsUntil) {
		return nil
	}
	out := make([]byte, len(g.modelsBody))
	copy(out, g.modelsBody)
	return out
}

func (g *Gateway) rememberModels(body []byte) {
	g.modelsMu.Lock()
	defer g.modelsMu.Unlock()
	g.modelsBody = append([]byte(nil), body...)
	g.modelsUntil = time.Now().Add(5 * time.Minute)
}

func looksLikeModelCatalog(body []byte) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return false
	}
	_, ok := m["models"]
	return ok
}

func (g *Gateway) Probe(ctx context.Context, up store.Upstream, apiKey string) (int, []byte, error) {
	body := []byte(`{"state":"ping","model":"jev-latest","questions":{"ok":{"type":"noul","instructions":"This is a connectivity probe"}}}`)
	choice, err := g.pickExit(ctx, up, nil)
	if err != nil {
		return 0, nil, err
	}
	status, resp, _, lat, ferr := g.forward(ctx, http.MethodPost, "/v1/systemone", body, apiKey, "probe", choice.Proxy)
	if ferr != nil {
		g.markProxyTransportErr(ctx, choice, ferr)
		return status, resp, ferr
	}
	if status >= 200 && status < 300 {
		g.markProxyOK(ctx, choice, lat)
	}
	return status, resp, ferr
}

func (g *Gateway) pickExit(ctx context.Context, up store.Upstream, exclude map[int64]struct{}) (outproxy.Choice, error) {
	if g.Picker == nil {
		return outproxy.Choice{Direct: true}, nil
	}
	return g.Picker.Pick(ctx, up, exclude)
}

func (g *Gateway) markProxyTransportErr(ctx context.Context, choice outproxy.Choice, err error) {
	if choice.Proxy == nil || g.Store == nil {
		return
	}
	_ = g.Store.TouchProxyErr(ctx, choice.Proxy.ID, err.Error(), outproxy.CooldownMS())
}

func (g *Gateway) markProxyOK(ctx context.Context, choice outproxy.Choice, lat int64) {
	if choice.Proxy == nil || g.Store == nil {
		return
	}
	_ = g.Store.TouchProxyOK(ctx, choice.Proxy.ID, "", "", lat)
}

func (g *Gateway) clientFor(via *store.Proxy) (*http.Client, error) {
	if g.Clients != nil {
		return g.Clients.Get(via)
	}
	if via == nil {
		return g.Client, nil
	}
	return outproxy.NewClient(g.Timeout, via)
}

func (g *Gateway) forward(ctx context.Context, method, path string, body []byte, apiKey, requestID string, via *store.Proxy) (int, []byte, http.Header, int64, error) {
	start := time.Now()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, g.Upstream+path, rdr)
	if err != nil {
		return 0, nil, nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if requestID != "" {
		req.Header.Set("X-Request-Id", requestID)
	}
	cli, err := g.clientFor(via)
	if err != nil {
		return 0, nil, nil, 0, err
	}
	resp, err := cli.Do(req)
	lat := time.Since(start).Milliseconds()
	if err != nil {
		return 0, nil, nil, lat, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return resp.StatusCode, nil, resp.Header, lat, err
	}
	return resp.StatusCode, b, resp.Header.Clone(), lat, nil
}

func (g *Gateway) copyUpstream(w http.ResponseWriter, status int, hdr http.Header, body []byte) {
	for _, k := range []string{"Content-Type", "Retry-After"} {
		if v := hdr.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func (g *Gateway) logFail(ctx context.Context, user store.UserKey, up *int64, model string, lat int64, status int, msg, rid string) {
	g.logFailID(ctx, user.ID, up, model, lat, status, msg, rid)
}

func (g *Gateway) logFailID(ctx context.Context, userID int64, up *int64, model string, lat int64, status int, msg, rid string) {
	_ = g.Store.InsertLog(ctx, store.UsageLog{
		UserKeyID:  userID,
		UpstreamID: up,
		Model:      model,
		LatencyMS:  lat,
		StatusCode: status,
		OK:         false,
		Error:      msg,
		RequestID:  rid,
	})
}

func validateSystemOne(body []byte) error {
	if len(bytes.TrimSpace(body)) == 0 {
		return errHTTP(400, "bad_request", "empty body")
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(body, &m); err != nil {
		return errHTTP(400, "bad_request", "body must be JSON object")
	}
	if _, ok := m["state"]; !ok {
		return errHTTP(400, "bad_request", "missing state")
	}
	if _, ok := m["questions"]; !ok {
		return errHTTP(400, "bad_request", "missing questions")
	}
	return nil
}

func parseUsage(body []byte) (in, out int64, model string) {
	var r upstreamResp
	if err := json.Unmarshal(body, &r); err != nil {
		return 0, 0, ""
	}
	return r.Usage.InputTokens, r.Usage.OutputTokens, r.Model
}

func modelOf(body []byte) string {
	var m struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &m)
	return m.Model
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		return s[:300]
	}
	return s
}

type httpErr struct {
	code       int
	kind       string
	msg        string
	retryAfter int
}

func (e httpErr) Error() string { return e.msg }

func errHTTP(code int, kind, msg string) httpErr {
	return httpErr{code: code, kind: kind, msg: msg}
}

func writeErr(w http.ResponseWriter, err error) {
	var he httpErr
	if !errors.As(err, &he) {
		he = errHTTP(500, "internal_error", err.Error())
	}
	if he.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(he.retryAfter))
	}
	writeJSON(w, he.code, map[string]any{
		"error": map[string]any{
			"type":    he.kind,
			"message": he.msg,
		},
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

func IsHTTPErr(err error) (httpErr, bool) {
	var he httpErr
	if errors.As(err, &he) {
		return he, true
	}
	return httpErr{}, false
}

func WriteError(w http.ResponseWriter, err error) { writeErr(w, err) }

func Unauthorized(msg string) error { return errHTTP(401, "invalid_api_key", msg) }
func Forbidden(msg string) error    { return errHTTP(403, "forbidden", msg) }
func BadRequest(msg string) error   { return errHTTP(400, "bad_request", msg) }
func NotFound(msg string) error     { return errHTTP(404, "not_found", msg) }
func Conflict(msg string) error     { return errHTTP(409, "conflict", msg) }
func Internal(msg string) error     { return errHTTP(500, "internal_error", msg) }
func Payment(msg string) error      { return errHTTP(402, "quota_exceeded", msg) }
func TooMany(msg string, ra int) error {
	e := errHTTP(429, "rate_limited", msg)
	e.retryAfter = ra
	return e
}
