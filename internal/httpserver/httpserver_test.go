package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"jevproxy/internal/cryptox"
	"jevproxy/internal/pool"
	"jevproxy/internal/proxy"
	"jevproxy/internal/ratelimit"
	"jevproxy/internal/store"
)

func TestParseKeyLines(t *testing.T) {
	got := parseKeyLines(`
# comment
prod-1 jev_aaaa1111
jev_bbbb2222
name,ts_cccc3333
jev_aaaa1111
not-a-key
user@example.com----apikey_2211cae1e540aa1541c9890895797b0e6458_6b6a2b8c5aa6caa69de18445f932a21ece3abae4d64f8e224f4ea0be10eedd52----key_1d38b5c22a5c25a45dc9047ad50cefd17fe----auto
`)
	if len(got) != 4 {
		t.Fatalf("got %d %+v", len(got), got)
	}
	if got[0].name != "prod-1" || got[0].key != "jev_aaaa1111" {
		t.Fatalf("first %+v", got[0])
	}
	if got[1].key != "jev_bbbb2222" || got[2].key != "ts_cccc3333" {
		t.Fatalf("rest %+v", got)
	}
	if got[3].name != "user@example.com" || !strings.HasPrefix(got[3].key, "apikey_") {
		t.Fatalf("dash name/key %+v", got[3])
	}
}

func testServer(t *testing.T, upstreamURL string) (*Server, *store.Store) {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	master, _ := cryptox.RandomKey32()
	box, _ := cryptox.NewAESGCM(master)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := pool.New(st, box)
	gw := proxy.New(st, p, ratelimit.New(), upstreamURL, 0, log)
	s := New(Config{Listen: ":0", AdminToken: "admintok"}, st, box, p, gw, log)
	return s, st
}

func adminReq(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("X-Admin-Token", "admintok")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAdminImportAndLogsFilter(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"model":"jev-1.13.0","answers":{"ok":{"noul":1}},"usage":{"input_tokens":9,"output_tokens":0}}`)
	}))
	defer up.Close()

	s, st := testServer(t, up.URL)
	h := s.Handler()

	rec := adminReq(h, http.MethodPost, "/admin/api/upstreams/import", `{
		"text":"a jev_one1111\njev_two2222\njev_one1111\nbadline",
		"weight":2,"rpm_limit":50
	}`)
	if rec.Code != 201 {
		t.Fatalf("import %d %s", rec.Code, rec.Body.String())
	}
	var imp struct {
		Created int `json:"created"`
		Skipped int `json:"skipped"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &imp); err != nil {
		t.Fatal(err)
	}
	if imp.Created != 2 || imp.Skipped != 0 {
		t.Fatalf("import %+v", imp)
	}

	rec = adminReq(h, http.MethodPost, "/admin/api/upstreams/import", `{
		"text":"jev_one1111\njev_three3333"
	}`)
	if rec.Code != 201 {
		t.Fatalf("reimport %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &imp); err != nil {
		t.Fatal(err)
	}
	if imp.Created != 1 || imp.Skipped != 1 {
		t.Fatalf("reimport %+v", imp)
	}

	rec = adminReq(h, http.MethodPost, "/admin/api/upstreams", `{"api_key":"jev_one1111"}`)
	if rec.Code != 409 {
		t.Fatalf("dup create %d %s", rec.Code, rec.Body.String())
	}

	rec = adminReq(h, http.MethodPost, "/admin/api/keys", `{"name":"alice","note":"sdk","rpm_limit":30,"token_quota":0}`)
	if rec.Code != 201 {
		t.Fatalf("create key %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID    int64  `json:"id"`
		Plain string `json:"plain"`
		Note  string `json:"note"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Plain == "" || created.Note != "sdk" {
		t.Fatalf("created %+v", created)
	}

	rec = adminReq(h, http.MethodPut, "/admin/api/keys/"+itoa(created.ID), `{"note":"prod","token_quota":100}`)
	if rec.Code != 200 {
		t.Fatalf("update key %d %s", rec.Code, rec.Body.String())
	}

	k, err := st.GetUserKey(context.Background(), created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if k.Note != "prod" || k.TokenQuota != 100 {
		t.Fatalf("user %+v", k)
	}

	rec = adminReq(h, http.MethodPost, "/admin/api/playground", `{
		"state":"hi","model":"jev-latest","questions":{"ok":{"type":"noul","instructions":"x"}}
	}`)
	if rec.Code != 200 {
		t.Fatalf("play %d %s", rec.Code, rec.Body.String())
	}
	var play map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &play); err != nil {
		t.Fatal(err)
	}
	if play["ok"] != true {
		t.Fatalf("play %+v", play)
	}

	rec = adminReq(h, http.MethodGet, "/admin/api/logs?ok=true&q=jev", "")
	if rec.Code != 200 {
		t.Fatalf("logs %d %s", rec.Code, rec.Body.String())
	}
	var logs struct {
		Total int              `json:"total"`
		Items []store.UsageLog `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &logs); err != nil {
		t.Fatal(err)
	}
	if logs.Total < 1 || len(logs.Items) < 1 {
		t.Fatalf("logs %+v", logs)
	}

	rec = adminReq(h, http.MethodGet, "/admin/api/stats", "")
	if rec.Code != 200 {
		t.Fatalf("stats %d %s", rec.Code, rec.Body.String())
	}
}

func TestAdminAuth(t *testing.T) {
	s, _ := testServer(t, "http://127.0.0.1:1")
	req := httptest.NewRequest(http.MethodGet, "/admin/api/stats", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("status %d", rec.Code)
	}
}

func authJSON(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if token != "" {
		req.Header.Set("X-Admin-Token", token)
	}
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAccountRoles(t *testing.T) {
	s, st := testServer(t, "http://127.0.0.1:1")
	h := s.Handler()

	rec := authJSON(h, http.MethodPost, "/admin/api/register", "", `{"username":"root","password":"password1"}`)
	if rec.Code != 201 {
		t.Fatalf("register admin %d %s", rec.Code, rec.Body.String())
	}
	var admin struct {
		Token   string `json:"token"`
		Account struct {
			Role string `json:"role"`
		} `json:"account"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &admin); err != nil {
		t.Fatal(err)
	}
	if admin.Account.Role != "admin" || admin.Token == "" {
		t.Fatalf("admin %+v", admin)
	}

	rec = authJSON(h, http.MethodPost, "/admin/api/register", "", `{"username":"alice","password":"password1"}`)
	if rec.Code != 201 {
		t.Fatalf("register user %d %s", rec.Code, rec.Body.String())
	}
	var user struct {
		Token   string `json:"token"`
		Account struct {
			ID   int64  `json:"id"`
			Role string `json:"role"`
		} `json:"account"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &user); err != nil {
		t.Fatal(err)
	}
	if user.Account.Role != "user" {
		t.Fatalf("user role %+v", user)
	}

	rec = authJSON(h, http.MethodPost, "/admin/api/login", "", `{"username":"alice","password":"nopepass1"}`)
	if rec.Code != 401 {
		t.Fatalf("bad login %d", rec.Code)
	}

	rec = authJSON(h, http.MethodGet, "/admin/api/upstreams", user.Token, "")
	if rec.Code != 403 {
		t.Fatalf("user upstreams %d %s", rec.Code, rec.Body.String())
	}
	rec = authJSON(h, http.MethodGet, "/admin/api/upstreams", admin.Token, "")
	if rec.Code != 200 {
		t.Fatalf("admin upstreams %d %s", rec.Code, rec.Body.String())
	}

	rec = authJSON(h, http.MethodPost, "/admin/api/keys", user.Token, `{"name":"broke"}`)
	if rec.Code != 402 {
		t.Fatalf("broke key %d %s", rec.Code, rec.Body.String())
	}

	rec = authJSON(h, http.MethodPost, "/admin/api/accounts/"+itoa(user.Account.ID)+"/credits", admin.Token, `{"delta":2}`)
	if rec.Code != 200 {
		t.Fatalf("credit %d %s", rec.Code, rec.Body.String())
	}

	rec = authJSON(h, http.MethodPost, "/admin/api/keys", user.Token, `{"name":"mine"}`)
	if rec.Code != 201 {
		t.Fatalf("user key %d %s", rec.Code, rec.Body.String())
	}
	var mine struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &mine); err != nil {
		t.Fatal(err)
	}
	k, err := st.GetUserKey(context.Background(), mine.ID)
	if err != nil {
		t.Fatal(err)
	}
	if k.OwnerID == nil || *k.OwnerID != user.Account.ID {
		t.Fatalf("owner %+v want %d", k.OwnerID, user.Account.ID)
	}

	rec = authJSON(h, http.MethodPost, "/admin/api/keys", admin.Token, `{"name":"other"}`)
	if rec.Code != 201 {
		t.Fatalf("admin key %d %s", rec.Code, rec.Body.String())
	}
	var other struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &other); err != nil {
		t.Fatal(err)
	}

	rec = authJSON(h, http.MethodGet, "/admin/api/keys", user.Token, "")
	if rec.Code != 200 {
		t.Fatalf("list %d %s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Items []struct {
			ID         int64   `json:"id"`
			Credits    *int64  `json:"credits"`
			CreditsUSD float64 `json:"credits_usd"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Items) != 1 || listed.Items[0].ID != mine.ID {
		t.Fatalf("scoped keys %+v", listed.Items)
	}
	if listed.Items[0].Credits == nil || *listed.Items[0].Credits != 2*store.CreditScale || listed.Items[0].CreditsUSD != 2 {
		t.Fatalf("key credits %+v", listed.Items[0])
	}

	rec = authJSON(h, http.MethodDelete, "/admin/api/keys/"+itoa(other.ID), user.Token, "")
	if rec.Code != 404 {
		t.Fatalf("user delete other %d %s", rec.Code, rec.Body.String())
	}
	if err := st.InsertLog(context.Background(), store.UsageLog{UserKeyID: mine.ID, OK: true, StatusCode: 200, Model: "jev"}); err != nil {
		t.Fatal(err)
	}
	if err := st.InsertLog(context.Background(), store.UsageLog{UserKeyID: other.ID, OK: true, StatusCode: 200, Model: "jev"}); err != nil {
		t.Fatal(err)
	}
	rec = authJSON(h, http.MethodGet, "/admin/api/logs", user.Token, "")
	if rec.Code != 200 {
		t.Fatalf("logs %d %s", rec.Code, rec.Body.String())
	}
	var logs struct {
		Total int              `json:"total"`
		Items []store.UsageLog `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &logs); err != nil {
		t.Fatal(err)
	}
	if logs.Total != 1 || len(logs.Items) != 1 || logs.Items[0].UserKeyID != mine.ID {
		t.Fatalf("scoped logs %+v", logs)
	}
}

func TestRedeemCodes(t *testing.T) {
	s, st := testServer(t, "http://127.0.0.1:1")
	h := s.Handler()

	rec := authJSON(h, http.MethodPost, "/admin/api/register", "", `{"username":"root","password":"password1"}`)
	if rec.Code != 201 {
		t.Fatalf("admin %d %s", rec.Code, rec.Body.String())
	}
	var admin struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &admin); err != nil {
		t.Fatal(err)
	}
	rec = authJSON(h, http.MethodPost, "/admin/api/register", "", `{"username":"alice","password":"password1"}`)
	if rec.Code != 201 {
		t.Fatalf("user %d %s", rec.Code, rec.Body.String())
	}
	var user struct {
		Token   string `json:"token"`
		Account struct {
			ID int64 `json:"id"`
		} `json:"account"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &user); err != nil {
		t.Fatal(err)
	}

	rec = authJSON(h, http.MethodPost, "/admin/api/redeem-codes", user.Token, `{"credits":5,"count":1}`)
	if rec.Code != 403 {
		t.Fatalf("user create %d %s", rec.Code, rec.Body.String())
	}
	rec = authJSON(h, http.MethodPost, "/admin/api/redeem", "admintok", `{"code":"RC-ABCD-EFGH-JKLM"}`)
	if rec.Code != 400 {
		t.Fatalf("break glass %d %s", rec.Code, rec.Body.String())
	}

	rec = authJSON(h, http.MethodPost, "/admin/api/redeem-codes", admin.Token, `{"credits":5,"count":2,"note":"batch"}`)
	if rec.Code != 201 {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	var batch struct {
		Codes []string `json:"codes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Codes) != 2 || normalizeRedeem(batch.Codes[0]) == "" {
		t.Fatalf("codes %+v", batch.Codes)
	}

	messy := strings.ToLower(strings.ReplaceAll(batch.Codes[0], "-", " "))
	rec = authJSON(h, http.MethodPost, "/admin/api/redeem", user.Token, `{"code":"`+messy+`"}`)
	if rec.Code != 200 {
		t.Fatalf("redeem %d %s", rec.Code, rec.Body.String())
	}
	var redeemed struct {
		AddedUSD   float64 `json:"added_usd"`
		CreditsUSD float64 `json:"credits_usd"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &redeemed); err != nil {
		t.Fatal(err)
	}
	if redeemed.AddedUSD != 5 || redeemed.CreditsUSD != 5 {
		t.Fatalf("balance %+v", redeemed)
	}
	acc, err := st.GetAccount(context.Background(), user.Account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if acc.Credits != 5*store.CreditScale {
		t.Fatalf("stored %d", acc.Credits)
	}

	rec = authJSON(h, http.MethodPost, "/admin/api/redeem", user.Token, `{"code":"`+batch.Codes[0]+`"}`)
	if rec.Code != 409 {
		t.Fatalf("reuse %d %s", rec.Code, rec.Body.String())
	}
	rec = authJSON(h, http.MethodPost, "/admin/api/redeem", user.Token, `{"code":"nope"}`)
	if rec.Code != 400 {
		t.Fatalf("bad code %d %s", rec.Code, rec.Body.String())
	}

	rec = authJSON(h, http.MethodGet, "/admin/api/redeem-codes", admin.Token, "")
	if rec.Code != 200 {
		t.Fatalf("list %d %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"redeemed_by":`+itoa(user.Account.ID))) {
		t.Fatalf("list body %s", rec.Body.String())
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(batch.Codes[0])) {
		t.Fatalf("plaintext leaked %s", rec.Body.String())
	}
}

func TestPlaygroundSpendsAccountCredits(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"model":"jev-1.13.0","answers":{"ok":{"noul":1}},"usage":{"input_tokens":1000,"output_tokens":4}}`)
	}))
	defer up.Close()

	s, st := testServer(t, up.URL)
	h := s.Handler()
	body := `{"state":"hi","model":"jev-latest","questions":{"ok":{"type":"noul","instructions":"x"}}}`

	rec := adminReq(h, http.MethodPost, "/admin/api/upstreams", `{"name":"u","api_key":"jev_play1111"}`)
	if rec.Code != 201 {
		t.Fatalf("upstream %d %s", rec.Code, rec.Body.String())
	}

	rec = authJSON(h, http.MethodPost, "/admin/api/register", "", `{"username":"alice","password":"password1"}`)
	if rec.Code != 201 {
		t.Fatalf("register %d %s", rec.Code, rec.Body.String())
	}
	var user struct {
		Token   string `json:"token"`
		Account struct {
			ID int64 `json:"id"`
		} `json:"account"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &user); err != nil {
		t.Fatal(err)
	}

	rec = authJSON(h, http.MethodPost, "/admin/api/playground", user.Token, body)
	if rec.Code != 402 {
		t.Fatalf("broke play %d %s", rec.Code, rec.Body.String())
	}

	if _, err := st.AdjustCredits(context.Background(), user.Account.ID, 2*store.CreditScale, true); err != nil {
		t.Fatal(err)
	}
	rec = authJSON(h, http.MethodPost, "/admin/api/playground", user.Token, body)
	if rec.Code != 200 {
		t.Fatalf("play %d %s", rec.Code, rec.Body.String())
	}
	var play map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &play); err != nil {
		t.Fatal(err)
	}
	if play["ok"] != true {
		t.Fatalf("play %+v", play)
	}
	acc, err := st.GetAccount(context.Background(), user.Account.ID)
	if err != nil {
		t.Fatal(err)
	}
	// 1000 input tokens * $42 / 1e9 = 42 micro-credits.
	want := 2*store.CreditScale - 42
	if acc.Credits != want {
		t.Fatalf("credits %d want %d", acc.Credits, want)
	}

	before, err := st.GetAccount(context.Background(), user.Account.ID)
	if err != nil {
		t.Fatal(err)
	}
	rec = adminReq(h, http.MethodPost, "/admin/api/playground", body)
	if rec.Code != 200 {
		t.Fatalf("break-glass play %d %s", rec.Code, rec.Body.String())
	}
	after, err := st.GetAccount(context.Background(), user.Account.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Credits != before.Credits {
		t.Fatalf("break-glass billed %d -> %d", before.Credits, after.Credits)
	}
}

func TestPlaygroundValidatesBody(t *testing.T) {
	s, _ := testServer(t, "http://127.0.0.1:1")
	rec := adminReq(s.Handler(), http.MethodPost, "/admin/api/playground", `{"foo":1}`)
	if rec.Code != 200 {
		t.Fatalf("status %d %s", rec.Code, rec.Body.String())
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte(`"ok":false`)) {
		t.Fatalf("body %s", rec.Body.String())
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestAdminProxyCRUDAndBind(t *testing.T) {
	s, st := testServer(t, "http://127.0.0.1:1")
	h := s.Handler()

	rec := adminReq(h, http.MethodPost, "/admin/api/proxies", `{"url":"http://user:pass@10.1.2.3:8080","name":"us-1"}`)
	if rec.Code != 201 {
		t.Fatalf("create %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ID       int64  `json:"id"`
		Protocol string `json:"protocol"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Name     string `json:"name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 || created.Host != "10.1.2.3" || created.Port != 8080 || created.Username != "user" || created.Name != "us-1" {
		t.Fatalf("created %+v", created)
	}

	rec = adminReq(h, http.MethodPost, "/admin/api/proxies", `{"url":"http://user:pass@10.1.2.3:8080"}`)
	if rec.Code != 409 {
		t.Fatalf("dup %d %s", rec.Code, rec.Body.String())
	}

	rec = adminReq(h, http.MethodPost, "/admin/api/proxies/import", `{"text":"socks5://127.0.0.1:1080\nhttp://user:pass@10.1.2.3:8080\nbadline"}`)
	if rec.Code != 201 {
		t.Fatalf("import %d %s", rec.Code, rec.Body.String())
	}
	var imp struct {
		Created int `json:"created"`
		Skipped int `json:"skipped"`
		Failed  int `json:"failed"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &imp); err != nil {
		t.Fatal(err)
	}
	if imp.Created != 1 || imp.Skipped != 1 || imp.Failed != 1 {
		t.Fatalf("import %+v", imp)
	}

	rec = adminReq(h, http.MethodGet, "/admin/api/proxies", "")
	if rec.Code != 200 {
		t.Fatalf("list %d %s", rec.Code, rec.Body.String())
	}

	rec = adminReq(h, http.MethodPost, "/admin/api/upstreams", `{"api_key":"jev_proxybind1","proxy_id":`+itoa(created.ID)+`}`)
	if rec.Code != 201 {
		t.Fatalf("up create %d %s", rec.Code, rec.Body.String())
	}
	var up struct {
		ID      int64  `json:"id"`
		ProxyID *int64 `json:"proxy_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &up); err != nil {
		t.Fatal(err)
	}
	if up.ProxyID == nil || *up.ProxyID != created.ID {
		t.Fatalf("bound %+v", up.ProxyID)
	}

	rec = adminReq(h, http.MethodPut, "/admin/api/upstreams/"+itoa(up.ID), `{"proxy_id":0}`)
	if rec.Code != 200 {
		t.Fatalf("force direct %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &up); err != nil {
		t.Fatal(err)
	}
	if up.ProxyID == nil || *up.ProxyID != 0 {
		t.Fatalf("direct %+v", up.ProxyID)
	}

	rec = adminReq(h, http.MethodPut, "/admin/api/upstreams/"+itoa(up.ID), `{"proxy_id":null}`)
	if rec.Code != 200 {
		t.Fatalf("pool %d %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &up); err != nil {
		t.Fatal(err)
	}
	if up.ProxyID != nil {
		t.Fatalf("pool mode want nil got %+v", up.ProxyID)
	}

	rec = adminReq(h, http.MethodPut, "/admin/api/upstreams/"+itoa(up.ID), `{"proxy_id":999}`)
	if rec.Code != 400 {
		t.Fatalf("missing proxy %d %s", rec.Code, rec.Body.String())
	}

	rec = adminReq(h, http.MethodDelete, "/admin/api/proxies/"+itoa(created.ID), "")
	if rec.Code != 200 {
		t.Fatalf("del %d %s", rec.Code, rec.Body.String())
	}
	_, err := st.GetProxy(context.Background(), created.ID)
	if err != store.ErrNotFound {
		t.Fatalf("deleted err %v", err)
	}
}
