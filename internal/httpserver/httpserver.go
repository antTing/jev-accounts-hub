package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"jevproxy/internal/adminui"
	"jevproxy/internal/cryptox"
	"jevproxy/internal/pool"
	"jevproxy/internal/proxy"
	"jevproxy/internal/store"
)

type Server struct {
	cfg        Config
	store      *store.Store
	box        *cryptox.AESGCM
	pool       *pool.Pool
	gw         *proxy.Gateway
	log        *slog.Logger
	httpServer *http.Server
}

type Config struct {
	Listen       string
	AdminToken   string
	Debug        bool
	OpenRegister bool
}

func New(cfg Config, st *store.Store, box *cryptox.AESGCM, p *pool.Pool, gw *proxy.Gateway, log *slog.Logger) *Server {
	return &Server{cfg: cfg, store: st, box: box, pool: p, gw: gw, log: log}
}

func (s *Server) Handler() http.Handler {
	if !s.cfg.Debug {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(s.requestID())
	r.Use(s.accessLog())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	v1 := r.Group("/v1")
	v1.POST("/systemone", s.handleSystemOne)
	v1.GET("/models", s.handleModels)

	r.GET("/admin/api/auth-info", s.authInfo)
	r.POST("/admin/api/register", s.register)
	r.POST("/admin/api/login", s.login)

	authed := r.Group("/admin/api")
	authed.Use(s.requireAccount())
	authed.POST("/logout", s.logout)
	authed.POST("/password", s.changePassword)
	authed.GET("/me", s.me)
	authed.GET("/stats", s.adminStats)
	authed.GET("/keys", s.adminListKeys)
	authed.POST("/keys", s.adminCreateKey)
	authed.PUT("/keys/:id", s.adminUpdateKey)
	authed.DELETE("/keys/:id", s.adminDeleteKey)
	authed.POST("/keys/:id/reset-usage", s.adminResetKeyUsage)
	authed.GET("/logs", s.adminLogs)
	authed.GET("/credits", s.myCredits)
	authed.GET("/ledger", s.myLedger)
	authed.POST("/redeem", s.redeemCode)
	authed.POST("/playground", s.adminPlayground)

	admin := r.Group("/admin/api")
	admin.Use(s.requireAccount())
	admin.Use(s.requireRoleAdmin())
	admin.GET("/upstreams", s.adminListUpstreams)
	admin.POST("/upstreams", s.adminCreateUpstream)
	admin.POST("/upstreams/import", s.adminImportUpstreams)
	admin.POST("/upstreams/probe-all", s.adminProbeAll)
	admin.PUT("/upstreams/:id", s.adminUpdateUpstream)
	admin.DELETE("/upstreams/:id", s.adminDeleteUpstream)
	admin.POST("/upstreams/:id/probe", s.adminProbeUpstream)
	admin.GET("/proxies", s.adminListProxies)
	admin.POST("/proxies", s.adminCreateProxy)
	admin.POST("/proxies/import", s.adminImportProxies)
	admin.PUT("/proxies/:id", s.adminUpdateProxy)
	admin.DELETE("/proxies/:id", s.adminDeleteProxy)
	admin.POST("/proxies/:id/probe", s.adminProbeProxy)
	admin.GET("/accounts", s.adminListAccounts)
	admin.POST("/accounts/:id/status", s.adminSetAccountStatus)
	admin.POST("/accounts/:id/credits", s.adminAdjustCredits)
	admin.GET("/accounts/:id/ledger", s.adminListLedger)
	admin.GET("/redeem-codes", s.adminListRedeemCodes)
	admin.POST("/redeem-codes", s.adminCreateRedeemCodes)

	r.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(200, adminui.IndexHTML)
	})
	r.GET("/admin", func(c *gin.Context) {
		c.Redirect(http.StatusFound, "/")
	})

	return r
}

func (s *Server) Start() error {
	s.httpServer = &http.Server{
		Addr:              s.cfg.Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return err
	}
	s.log.Info("listening", "addr", ln.Addr().String())
	return s.httpServer.Serve(ln)
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader("X-Request-Id")
		if id == "" {
			id = uuid.NewString()
		}
		c.Header("X-Request-Id", id)
		c.Set("request_id", id)
		c.Next()
	}
}

func (s *Server) accessLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		s.log.Info("http",
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", c.Writer.Status(),
			"ms", time.Since(start).Milliseconds(),
			"request_id", c.GetString("request_id"),
		)
	}
}

const sessionTTL = 14 * 24 * time.Hour

func readToken(c *gin.Context) string {
	tok := strings.TrimSpace(c.GetHeader("X-Admin-Token"))
	if tok == "" {
		if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			tok = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
	}
	return tok
}

func (s *Server) requireAccount() gin.HandlerFunc {
	return func(c *gin.Context) {
		tok := readToken(c)
		if cryptox.EqualToken(tok, strings.TrimSpace(s.cfg.AdminToken)) {
			c.Set("role", store.RoleAdmin)
			c.Set("break_glass", true)
			c.Next()
			return
		}
		if tok == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": gin.H{"type": "unauthorized", "message": "login required"}})
			return
		}
		acc, err := s.store.AccountBySession(c.Request.Context(), cryptox.HashAPIKey(tok))
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": gin.H{"type": "unauthorized", "message": "login required"}})
			return
		}
		c.Set("account", acc)
		c.Set("role", acc.Role)
		c.Next()
	}
}

func (s *Server) requireRoleAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetString("role") != store.RoleAdmin {
			c.AbortWithStatusJSON(403, gin.H{"error": gin.H{"type": "forbidden", "message": "admin only"}})
			return
		}
		c.Next()
	}
}

func (s *Server) currentAccount(c *gin.Context) (store.Account, bool) {
	v, ok := c.Get("account")
	if !ok {
		return store.Account{}, false
	}
	acc, ok := v.(store.Account)
	return acc, ok
}

func (s *Server) isAdmin(c *gin.Context) bool {
	return c.GetString("role") == store.RoleAdmin
}

type authReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func validUsername(name string) bool {
	n := utf8.RuneCountInString(name)
	if n < 3 || n > 32 {
		return false
	}
	for _, r := range name {
		if r > 127 || !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}

func (s *Server) authInfo(c *gin.Context) {
	n, err := s.store.CountAccounts(c.Request.Context())
	if err != nil {
		s.fail(c, 500, "internal error")
		return
	}
	c.JSON(200, gin.H{"open_register": s.cfg.OpenRegister || n == 0})
}

func (s *Server) allowAuth(c *gin.Context, kind string, limit int) bool {
	ip := c.ClientIP()
	if ip == "" {
		ip = "unknown"
	}
	ok, wait := s.gw.Limit.AllowWindow("auth:"+kind+":"+ip, limit, time.Hour)
	if ok {
		return true
	}
	c.Header("Retry-After", strconv.Itoa(int(wait.Seconds())))
	s.fail(c, 429, "尝试过于频繁，请稍后再试")
	return false
}

func (s *Server) register(c *gin.Context) {
	if !s.allowAuth(c, "register", 5) {
		return
	}
	var req authReq
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	name := strings.TrimSpace(req.Username)
	pass := req.Password
	if !validUsername(name) {
		s.fail(c, 400, "用户名需 3-32 位字母、数字、_-.")
		return
	}
	if utf8.RuneCountInString(pass) < 8 || len(pass) > 128 {
		s.fail(c, 400, "密码至少 8 位")
		return
	}
	hash, err := cryptox.HashPassword(pass)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	n, err := s.store.CountAccounts(c.Request.Context())
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("count accounts", "err", err)
		return
	}
	if n > 0 && !s.cfg.OpenRegister {
		s.fail(c, 403, "注册已关闭")
		return
	}
	var id int64
	if n == 0 {
		id, err = s.store.InsertBootstrapAccount(c.Request.Context(), name, hash)
	} else {
		id, err = s.store.InsertAccount(c.Request.Context(), name, hash, store.RoleUser)
	}
	if errors.Is(err, store.ErrConflict) {
		s.fail(c, 409, "用户名已存在")
		return
	}
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	tok, acc, err := s.issueSession(c, id)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	c.JSON(201, gin.H{"token": tok, "account": accountDTO(acc)})
}

func (s *Server) login(c *gin.Context) {
	if !s.allowAuth(c, "login", 10) {
		return
	}
	var req authReq
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	acc, err := s.store.GetAccountByUsername(c.Request.Context(), strings.TrimSpace(req.Username))
	if err != nil || acc.Status != "active" || !cryptox.CheckPassword(acc.PasswordHash, req.Password) {
		s.fail(c, 401, "用户名或密码错误")
		return
	}
	tok, acc, err := s.issueSession(c, acc.ID)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	c.JSON(200, gin.H{"token": tok, "account": accountDTO(acc)})
}

func (s *Server) changePassword(c *gin.Context) {
	if c.GetBool("break_glass") {
		s.fail(c, 400, "应急口令没有密码可改")
		return
	}
	acc, ok := s.currentAccount(c)
	if !ok {
		s.fail(c, 401, "login required")
		return
	}
	var req struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	if !cryptox.CheckPassword(acc.PasswordHash, req.Old) {
		s.fail(c, 401, "原密码错误")
		return
	}
	if utf8.RuneCountInString(req.New) < 8 || len(req.New) > 128 {
		s.fail(c, 400, "密码至少 8 位")
		return
	}
	if req.New == req.Old {
		s.fail(c, 400, "新密码不能与原密码相同")
		return
	}
	hash, err := cryptox.HashPassword(req.New)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("hash password", "err", err)
		return
	}
	if err := s.store.UpdatePassword(c.Request.Context(), acc.ID, hash); err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("update password", "err", err)
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (s *Server) adminSetAccountStatus(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		s.fail(c, 400, "bad id")
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	if req.Status != "active" && req.Status != "disabled" {
		s.fail(c, 400, "status 只能是 active 或 disabled")
		return
	}
	if acc, ok := s.currentAccount(c); ok && acc.ID == id && req.Status != "active" {
		s.fail(c, 400, "不能停用自己")
		return
	}
	if err := s.store.SetAccountStatus(c.Request.Context(), id, req.Status); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(c, 404, "not found")
			return
		}
		s.fail(c, 500, "internal error")
		s.log.Error("account status", "err", err)
		return
	}
	c.JSON(200, gin.H{"id": id, "status": req.Status})
}

func (s *Server) logout(c *gin.Context) {
	tok := readToken(c)
	if tok != "" && !c.GetBool("break_glass") {
		_ = s.store.DeleteSession(c.Request.Context(), cryptox.HashAPIKey(tok))
	}
	c.JSON(200, gin.H{"ok": true})
}

func (s *Server) me(c *gin.Context) {
	if c.GetBool("break_glass") {
		c.JSON(200, gin.H{"username": "admin", "role": store.RoleAdmin, "break_glass": true})
		return
	}
	acc, ok := s.currentAccount(c)
	if !ok {
		s.fail(c, 401, "login required")
		return
	}
	c.JSON(200, accountDTO(acc))
}

func (s *Server) issueSession(c *gin.Context, accountID int64) (string, store.Account, error) {
	plain, err := cryptox.RandomString(48)
	if err != nil {
		return "", store.Account{}, err
	}
	exp := time.Now().Add(sessionTTL).UnixMilli()
	if err := s.store.InsertSession(c.Request.Context(), cryptox.HashAPIKey(plain), accountID, exp); err != nil {
		return "", store.Account{}, err
	}
	acc, err := s.store.GetAccount(c.Request.Context(), accountID)
	if err != nil {
		return "", store.Account{}, err
	}
	return plain, acc, nil
}

func accountDTO(a store.Account) gin.H {
	return gin.H{
		"id": a.ID, "username": a.Username, "role": a.Role, "status": a.Status,
		"credits": a.Credits, "credits_usd": float64(a.Credits) / float64(store.CreditScale),
	}
}

func (s *Server) handleSystemOne(c *gin.Context) {
	user, err := s.gw.Authenticate(c.Request)
	if err != nil {
		proxy.WriteError(c.Writer, err)
		c.Abort()
		return
	}
	s.gw.SystemOne(c.Writer, c.Request, user, c.GetString("request_id"))
}

func (s *Server) handleModels(c *gin.Context) {
	user, err := s.gw.Authenticate(c.Request)
	if err != nil {
		proxy.WriteError(c.Writer, err)
		c.Abort()
		return
	}
	s.gw.Models(c.Writer, c.Request, user, c.GetString("request_id"))
}

func (s *Server) adminStats(c *gin.Context) {
	var (
		st  store.Stats
		err error
	)
	if acc, ok := s.currentAccount(c); ok && !s.isAdmin(c) {
		st, err = s.store.StatsFor(c.Request.Context(), acc.ID)
	} else {
		st, err = s.store.Stats(c.Request.Context())
	}
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	c.JSON(200, st)
}

type upstreamDTO struct {
	ID            int64   `json:"id"`
	Name          string  `json:"name"`
	Mask          string  `json:"mask"`
	Weight        int     `json:"weight"`
	RPMLimit      int     `json:"rpm_limit"`
	Status        string  `json:"status"`
	FailCount     int     `json:"fail_count"`
	CooldownUntil int64   `json:"cooldown_until"`
	LastOKAt      *int64  `json:"last_ok_at"`
	LastErrAt     *int64  `json:"last_err_at"`
	LastErr       string  `json:"last_err"`
	CreatedAt     int64   `json:"created_at"`
	ProxyID       *int64  `json:"proxy_id"`
	InputTokens   int64   `json:"input_tokens"`
	Requests      int64   `json:"requests"`
	EstUSD        float64 `json:"est_usd"`
}

// TypeSafe public price: $42 per billion input tokens. Output is free.
// This estimates only traffic recorded by this gateway, not the official balance.
const inputUSDPerToken = 42.0 / 1_000_000_000

func toUpstreamDTO(u store.Upstream) upstreamDTO {
	return upstreamDTO{
		ID: u.ID, Name: u.Name, Mask: u.Mask(), Weight: u.Weight, RPMLimit: u.RPMLimit,
		Status: u.Status, FailCount: u.FailCount, CooldownUntil: u.CooldownUntil,
		LastOKAt: u.LastOKAt, LastErrAt: u.LastErrAt, LastErr: u.LastErr, CreatedAt: u.CreatedAt,
		ProxyID: u.ProxyID,
	}
}

func (s *Server) adminListUpstreams(c *gin.Context) {
	items, err := s.store.ListUpstreams(c.Request.Context())
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	usage, err := s.store.UpstreamUsage(c.Request.Context())
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	out := make([]upstreamDTO, 0, len(items))
	for _, item := range items {
		dto := toUpstreamDTO(item)
		if u, ok := usage[item.ID]; ok {
			dto.InputTokens = u.InputTokens
			dto.Requests = u.Requests
			dto.EstUSD = float64(u.InputTokens) * inputUSDPerToken
		}
		out = append(out, dto)
	}
	c.JSON(200, gin.H{"items": out})
}

type upstreamReq struct {
	Name     string        `json:"name"`
	APIKey   string        `json:"api_key"`
	Weight   *int          `json:"weight"`
	RPMLimit *int          `json:"rpm_limit"`
	Status   string        `json:"status"`
	ProxyID  optionalInt64 `json:"proxy_id"`
}

func (s *Server) adminCreateUpstream(c *gin.Context) {
	var req upstreamReq
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	key := strings.TrimSpace(req.APIKey)
	if key == "" {
		s.fail(c, 400, "api_key required")
		return
	}
	if !looksLikeUpstreamKey(key) {
		s.fail(c, 400, "api_key must look like jev_ / ts_ / apikey_")
		return
	}
	weight, rpm := 1, 1000
	if req.Weight != nil {
		weight = *req.Weight
	}
	if req.RPMLimit != nil {
		rpm = *req.RPMLimit
	}
	proxyID, err := s.validatedProxyID(c, req.ProxyID)
	if err != nil {
		return
	}
	u, err := s.insertUpstream(c.Request.Context(), strings.TrimSpace(req.Name), key, weight, rpm, req.Status, proxyID)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.fail(c, 409, "upstream key already imported")
			return
		}
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	c.JSON(201, toUpstreamDTO(u))
}

func (s *Server) insertUpstream(ctx context.Context, name, key string, weight, rpm int, status string, proxyID *int64) (store.Upstream, error) {
	hash := cryptox.HashAPIKey(key)
	exists, err := s.store.UpstreamHashExists(ctx, hash)
	if err != nil {
		return store.Upstream{}, err
	}
	if exists {
		return store.Upstream{}, store.ErrConflict
	}
	enc, err := s.box.Encrypt([]byte(key))
	if err != nil {
		return store.Upstream{}, err
	}
	prefix, last4 := store.PrefixLast4(key)
	if name == "" {
		name = "key-" + last4
	}
	id, err := s.store.InsertUpstream(ctx, store.Upstream{
		Name: name, KeyEnc: enc, KeyPrefix: prefix, KeyLast4: last4, KeyHash: hash,
		Weight: weight, RPMLimit: rpm, Status: status, ProxyID: proxyID,
	})
	if err != nil {
		return store.Upstream{}, err
	}
	return s.store.GetUpstream(ctx, id)
}

func (s *Server) adminUpdateUpstream(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		s.fail(c, 400, "bad id")
		return
	}
	cur, err := s.store.GetUpstream(c.Request.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(c, 404, "not found")
		return
	}
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	var req upstreamReq
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = cur.Name
	}
	status := req.Status
	if status == "" {
		status = cur.Status
	}
	weight, rpm := cur.Weight, cur.RPMLimit
	if req.Weight != nil {
		weight = *req.Weight
	}
	if req.RPMLimit != nil {
		rpm = *req.RPMLimit
	}
	var enc []byte
	prefix, last4, hash := cur.KeyPrefix, cur.KeyLast4, ""
	if k := strings.TrimSpace(req.APIKey); k != "" {
		if !looksLikeUpstreamKey(k) {
			s.fail(c, 400, "api_key must look like jev_ / ts_ / apikey_")
			return
		}
		enc, err = s.box.Encrypt([]byte(k))
		if err != nil {
			s.fail(c, 500, "internal error")
			s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
			return
		}
		prefix, last4 = store.PrefixLast4(k)
		hash = cryptox.HashAPIKey(k)
	}
	var proxyID *int64
	setProxy := false
	if req.ProxyID.set {
		pid, err := s.validatedProxyID(c, req.ProxyID)
		if err != nil {
			return
		}
		proxyID = pid
		setProxy = true
	}
	if err := s.store.UpdateUpstream(c.Request.Context(), id, name, weight, rpm, status, enc, prefix, last4, hash, proxyID, setProxy); err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	u, _ := s.store.GetUpstream(c.Request.Context(), id)
	c.JSON(200, toUpstreamDTO(u))
}

func (s *Server) adminDeleteUpstream(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		s.fail(c, 400, "bad id")
		return
	}
	if err := s.store.DeleteUpstream(c.Request.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(c, 404, "not found")
			return
		}
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (s *Server) adminProbeUpstream(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		s.fail(c, 400, "bad id")
		return
	}
	u, err := s.store.GetUpstream(c.Request.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(c, 404, "not found")
		return
	}
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	key, err := s.pool.Decrypt(u)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
	defer cancel()
	status, body, ferr := s.gw.Probe(ctx, u, key)
	ok := ferr == nil && status >= 200 && status < 300
	if ok {
		s.pool.MarkOK(c.Request.Context(), id)
	} else {
		msg := ""
		if ferr != nil {
			msg = ferr.Error()
		} else {
			msg = string(body)
			if len(msg) > 300 {
				msg = msg[:300]
			}
		}
		s.pool.MarkErr(c.Request.Context(), id, msg, status)
	}
	c.JSON(200, gin.H{
		"ok":          ok,
		"status_code": status,
		"error":       errString(ferr),
		"body":        clip(string(body), 800),
	})
}

type userKeyDTO struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	Mask       string  `json:"mask"`
	RPMLimit   int     `json:"rpm_limit"`
	TokenQuota int64   `json:"token_quota"`
	TokensUsed int64   `json:"tokens_used"`
	Status     string  `json:"status"`
	Note       string  `json:"note"`
	ExpiresAt  *int64  `json:"expires_at"`
	LastUsedAt *int64  `json:"last_used_at"`
	CreatedAt  int64   `json:"created_at"`
	OwnerID    *int64  `json:"owner_id"`
	Credits    *int64  `json:"credits"`
	CreditsUSD float64 `json:"credits_usd"`
	Plain      string  `json:"plain,omitempty"`
}

func toUserDTO(k store.UserKey, credits map[int64]int64) userKeyDTO {
	dto := userKeyDTO{
		ID: k.ID, Name: k.Name, Mask: k.Mask(), RPMLimit: k.RPMLimit,
		TokenQuota: k.TokenQuota, TokensUsed: k.TokensUsed, Status: k.Status, Note: k.Note,
		ExpiresAt: k.ExpiresAt, LastUsedAt: k.LastUsedAt, CreatedAt: k.CreatedAt,
		OwnerID: k.OwnerID,
	}
	if k.OwnerID != nil {
		if bal, ok := credits[*k.OwnerID]; ok {
			dto.Credits = &bal
			dto.CreditsUSD = float64(bal) / float64(store.CreditScale)
		}
	}
	return dto
}

func (s *Server) adminListKeys(c *gin.Context) {
	var (
		items []store.UserKey
		err   error
	)
	if acc, ok := s.currentAccount(c); ok && !s.isAdmin(c) {
		items, err = s.store.ListUserKeysByOwner(c.Request.Context(), acc.ID)
	} else {
		items, err = s.store.ListUserKeys(c.Request.Context())
	}
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	credits, err := s.ownerCredits(c.Request.Context(), items)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	out := make([]userKeyDTO, 0, len(items))
	for _, k := range items {
		out = append(out, toUserDTO(k, credits))
	}
	c.JSON(200, gin.H{"items": out})
}

func (s *Server) ownerCredits(ctx context.Context, items []store.UserKey) (map[int64]int64, error) {
	out := map[int64]int64{}
	for _, k := range items {
		if k.OwnerID == nil {
			continue
		}
		if _, ok := out[*k.OwnerID]; ok {
			continue
		}
		acc, err := s.store.GetAccount(ctx, *k.OwnerID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[acc.ID] = acc.Credits
	}
	return out, nil
}

type keyReq struct {
	Name       string  `json:"name"`
	RPMLimit   *int    `json:"rpm_limit"`
	TokenQuota *int64  `json:"token_quota"`
	Status     string  `json:"status"`
	Note       *string `json:"note"`
	ExpiresAt  *int64  `json:"expires_at"`
	OwnerID    *int64  `json:"owner_id"`
}

func (s *Server) adminCreateKey(c *gin.Context) {
	var req keyReq
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		s.fail(c, 400, "invalid json")
		return
	}
	body, err := cryptox.RandomString(40)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	plain := "sk-jev-" + body
	prefix, last4 := store.PrefixLast4(plain)
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "user-" + last4
	}
	rpm := 60
	if req.RPMLimit != nil {
		rpm = *req.RPMLimit
	}
	if rpm < 1 || rpm > 100000 {
		s.fail(c, 400, "RPM 须为 1 到 100000")
		return
	}
	var quota int64
	if req.TokenQuota != nil {
		quota = *req.TokenQuota
	}
	if quota < 0 {
		s.fail(c, 400, "token 配额不能为负")
		return
	}
	note := ""
	if req.Note != nil {
		note = strings.TrimSpace(*req.Note)
	}
	uk := store.UserKey{
		Name: name, KeyHash: cryptox.HashAPIKey(plain), KeyPrefix: prefix, KeyLast4: last4,
		RPMLimit: rpm, TokenQuota: quota, Status: "active", Note: note, ExpiresAt: req.ExpiresAt,
	}
	ownerID := int64(0)
	if acc, ok := s.currentAccount(c); ok && !s.isAdmin(c) {
		ownerID = acc.ID
	} else if req.OwnerID != nil && *req.OwnerID > 0 {
		ownerID = *req.OwnerID
	} else if acc, ok := s.currentAccount(c); ok {
		ownerID = acc.ID
	}
	if ownerID == 0 {
		s.fail(c, 400, "请指定归属账号")
		return
	}
	owner, err := s.store.GetAccount(c.Request.Context(), ownerID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(c, 500, "internal error")
		s.log.Error("key owner", "err", err)
		return
	}
	if errors.Is(err, store.ErrNotFound) || owner.Status != "active" {
		s.fail(c, 400, "归属账号不存在或已停用")
		return
	}
	if owner.Credits <= 0 {
		s.fail(c, 402, "积分不足，无法创建 Key")
		return
	}
	uk.OwnerID = &ownerID
	if !s.isAdmin(c) {
		uk.TokenQuota = 0
		if uk.RPMLimit <= 0 || uk.RPMLimit > 120 {
			uk.RPMLimit = 60
		}
	}
	id, err := s.store.InsertUserKey(c.Request.Context(), uk)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	k, _ := s.store.GetUserKey(c.Request.Context(), id)
	credits, _ := s.ownerCredits(c.Request.Context(), []store.UserKey{k})
	dto := toUserDTO(k, credits)
	dto.Plain = plain
	c.JSON(201, dto)
}

func (s *Server) adminUpdateKey(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		s.fail(c, 400, "bad id")
		return
	}
	cur, err := s.store.GetUserKey(c.Request.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(c, 404, "not found")
		return
	}
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	userEdit := false
	if acc, ok := s.currentAccount(c); ok && !s.isAdmin(c) {
		if cur.OwnerID == nil || *cur.OwnerID != acc.ID {
			s.fail(c, 404, "not found")
			return
		}
		userEdit = true
	}
	var req keyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = cur.Name
	}
	status := req.Status
	if status == "" {
		status = cur.Status
	}
	rpm := cur.RPMLimit
	if req.RPMLimit != nil {
		rpm = *req.RPMLimit
	}
	if rpm < 1 || rpm > 100000 {
		s.fail(c, 400, "RPM 须为 1 到 100000")
		return
	}
	quota := cur.TokenQuota
	if req.TokenQuota != nil {
		quota = *req.TokenQuota
	}
	if quota < 0 {
		s.fail(c, 400, "token 配额不能为负")
		return
	}
	note := cur.Note
	if req.Note != nil {
		note = *req.Note
	}
	exp := cur.ExpiresAt
	if req.ExpiresAt != nil {
		exp = req.ExpiresAt
	}
	if userEdit {
		name = cur.Name
		status = cur.Status
		quota = cur.TokenQuota
		note = cur.Note
		exp = cur.ExpiresAt
		if req.RPMLimit == nil || *req.RPMLimit < 1 || *req.RPMLimit > 120 {
			s.fail(c, 400, "RPM 须为 1 到 120")
			return
		}
		rpm = *req.RPMLimit
	}
	if err := s.store.UpdateUserKey(c.Request.Context(), id, name, rpm, quota, status, exp, note); err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	k, _ := s.store.GetUserKey(c.Request.Context(), id)
	credits, _ := s.ownerCredits(c.Request.Context(), []store.UserKey{k})
	c.JSON(200, toUserDTO(k, credits))
}

func (s *Server) adminDeleteKey(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		s.fail(c, 400, "bad id")
		return
	}
	cur, err := s.store.GetUserKey(c.Request.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(c, 404, "not found")
		return
	}
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	if acc, ok := s.currentAccount(c); ok && !s.isAdmin(c) {
		if cur.OwnerID == nil || *cur.OwnerID != acc.ID {
			s.fail(c, 404, "not found")
			return
		}
	}
	if err := s.store.DeleteUserKey(c.Request.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(c, 404, "not found")
			return
		}
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (s *Server) adminResetKeyUsage(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		s.fail(c, 400, "bad id")
		return
	}
	if !s.isAdmin(c) {
		s.fail(c, 403, "admin only")
		return
	}
	if err := s.store.ResetTokens(c.Request.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(c, 404, "not found")
			return
		}
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	k, _ := s.store.GetUserKey(c.Request.Context(), id)
	credits, _ := s.ownerCredits(c.Request.Context(), []store.UserKey{k})
	c.JSON(200, toUserDTO(k, credits))
}

func (s *Server) adminLogs(c *gin.Context) {
	f := store.LogFilter{Limit: atoi(c.Query("limit"), 50), Offset: atoi(c.Query("offset"), 0), Q: c.Query("q")}
	if v := c.Query("user_key_id"); v != "" {
		f.UserKeyID, _ = strconv.ParseInt(v, 10, 64)
	}
	if acc, ok := s.currentAccount(c); ok && !s.isAdmin(c) {
		f.OwnerID = acc.ID
	}
	if s.isAdmin(c) {
		if v := c.Query("upstream_id"); v != "" {
			f.UpstreamID, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	if v := c.Query("ok"); v != "" {
		b := v == "1" || v == "true"
		f.OK = &b
	}
	switch c.Query("range") {
	case "1h":
		f.Since = time.Now().Add(-time.Hour).UnixMilli()
	case "24h":
		f.Since = time.Now().Add(-24 * time.Hour).UnixMilli()
	case "7d":
		f.Since = time.Now().Add(-7 * 24 * time.Hour).UnixMilli()
	}
	items, total, err := s.store.ListLogs(c.Request.Context(), f)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	names, err := s.logAccountNames(c.Request.Context(), items)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	out := make([]gin.H, 0, len(items))
	for _, it := range items {
		out = append(out, gin.H{
			"id": it.ID, "user_key_id": it.UserKeyID, "upstream_id": it.UpstreamID,
			"model": it.Model, "input_tokens": it.InputTokens, "output_tokens": it.OutputTokens,
			"latency_ms": it.LatencyMS, "status_code": it.StatusCode, "ok": it.OK,
			"error": it.Error, "request_id": it.RequestID, "created_at": it.CreatedAt,
			"credit_micro": it.CreditMicro, "account_id": it.AccountID,
			"account_name": names[it.AccountID],
		})
	}
	c.JSON(200, gin.H{"items": out, "total": total, "limit": f.Limit, "offset": f.Offset})
}

func (s *Server) logAccountNames(ctx context.Context, items []store.UsageLog) (map[int64]string, error) {
	names := map[int64]string{}
	for _, it := range items {
		if it.AccountID <= 0 {
			continue
		}
		if _, ok := names[it.AccountID]; ok {
			continue
		}
		acc, err := s.store.GetAccount(ctx, it.AccountID)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		names[acc.ID] = acc.Username
	}
	return names, nil
}

type importReq struct {
	Text     string `json:"text"`
	Weight   int    `json:"weight"`
	RPMLimit int    `json:"rpm_limit"`
}

func (s *Server) adminImportUpstreams(c *gin.Context) {
	var req importReq
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	lines := parseKeyLines(req.Text)
	if len(lines) == 0 {
		s.fail(c, 400, "no keys found")
		return
	}
	created, skipped := 0, 0
	var items []upstreamDTO
	for _, ln := range lines {
		u, err := s.insertUpstream(c.Request.Context(), ln.name, ln.key, req.Weight, req.RPMLimit, "active", nil)
		if err != nil {
			if errors.Is(err, store.ErrConflict) {
				skipped++
				continue
			}
			s.fail(c, 500, "internal error")
			s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
			return
		}
		items = append(items, toUpstreamDTO(u))
		created++
	}
	c.JSON(201, gin.H{"created": created, "skipped": skipped, "items": items})
}

func (s *Server) adminProbeAll(c *gin.Context) {
	items, err := s.store.ListUpstreams(c.Request.Context())
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	type probeOne struct {
		ID         int64  `json:"id"`
		OK         bool   `json:"ok"`
		StatusCode int    `json:"status_code"`
		Error      string `json:"error"`
	}
	out := make([]probeOne, 0, len(items))
	okN := 0
	for _, u := range items {
		if u.Status != "active" {
			continue
		}
		key, err := s.pool.Decrypt(u)
		if err != nil {
			out = append(out, probeOne{ID: u.ID, Error: err.Error()})
			continue
		}
		ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
		status, body, ferr := s.gw.Probe(ctx, u, key)
		cancel()
		ok := ferr == nil && status >= 200 && status < 300
		item := probeOne{ID: u.ID, OK: ok, StatusCode: status}
		if ok {
			s.pool.MarkOK(c.Request.Context(), u.ID)
			okN++
		} else {
			msg := errString(ferr)
			if msg == "" {
				msg = clip(string(body), 200)
			}
			item.Error = msg
			s.pool.MarkErr(c.Request.Context(), u.ID, msg, status)
		}
		out = append(out, item)
	}
	c.JSON(200, gin.H{"ok": okN, "total": len(out), "items": out})
}

func (s *Server) adminPlayground(c *gin.Context) {
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, 8<<20))
	if err != nil {
		s.fail(c, 400, "read body failed")
		return
	}
	acc, ok := s.currentAccount(c)
	if !ok {
		s.fail(c, 400, "应急口令没有账号，请登录后再试玩")
		return
	}
	enough, err := s.store.TrySpendCredits(c.Request.Context(), acc.ID, 0)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	if !enough {
		s.fail(c, 402, "积分不足")
		return
	}
	owner := acc.ID
	user := &store.UserKey{OwnerID: &owner}
	res := s.gw.Evaluate(c.Request.Context(), user, body, c.GetString("request_id"))
	if res.Status == 402 {
		s.fail(c, 402, "积分不足")
		return
	}
	status := res.Status
	if status == 0 {
		status = 502
	}
	var parsed any
	if len(res.Body) > 0 {
		_ = json.Unmarshal(res.Body, &parsed)
	}
	errMsg := ""
	if res.Err != nil {
		errMsg = res.Err.Error()
	}
	c.JSON(200, gin.H{
		"ok":            status >= 200 && status < 300,
		"status_code":   status,
		"latency_ms":    res.LatencyMS,
		"model":         res.Model,
		"input_tokens":  res.InputTokens,
		"output_tokens": res.OutputTokens,
		"upstream_id":   res.UpstreamID,
		"error":         errMsg,
		"body":          parsed,
	})
}

type parsedKey struct{ name, key string }

func parseKeyLines(text string) []parsedKey {
	var out []parsedKey
	seen := map[string]struct{}{}
	add := func(name, key string) {
		key = strings.TrimSpace(key)
		if !looksLikeUpstreamKey(key) {
			return
		}
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, parsedKey{name: strings.TrimSpace(name), key: key})
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := splitImportFields(line)
		var name string
		var keys []string
		for _, f := range fields {
			if looksLikeUpstreamKey(f) {
				keys = append(keys, f)
				continue
			}
			if name == "" && looksLikeAccountName(f) {
				name = f
			}
		}
		switch len(keys) {
		case 0:
			continue
		case 1:
			add(name, keys[0])
		default:
			for _, k := range keys {
				add(name, k)
			}
		}
	}
	return out
}

func splitImportFields(line string) []string {
	line = strings.ReplaceAll(line, "----", ",")
	return strings.FieldsFunc(line, func(r rune) bool {
		return r == ',' || r == ';' || r == '|' || unicode.IsSpace(r)
	})
}

func looksLikeAccountName(s string) bool {
	if s == "" || looksLikeUpstreamKey(s) {
		return false
	}
	if strings.HasPrefix(s, "key_") {
		return false
	}
	switch strings.ToLower(s) {
	case "auto", "manual", "true", "false":
		return false
	}
	return true
}

func looksLikeUpstreamKey(s string) bool {
	switch {
	case strings.HasPrefix(s, "jev_"), strings.HasPrefix(s, "ts_"):
		return len(s) >= 8
	case strings.HasPrefix(s, "apikey_"):
		return len(s) >= 12
	default:
		return false
	}
}

func (s *Server) validatedProxyID(c *gin.Context, opt optionalInt64) (*int64, error) {
	if !opt.set {
		return nil, nil
	}
	if opt.val == nil {
		return nil, nil
	}
	id := *opt.val
	if id == 0 {
		z := int64(0)
		return &z, nil
	}
	if _, err := s.store.GetProxy(c.Request.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(c, 400, "proxy not found")
			return nil, err
		}
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return nil, err
	}
	return &id, nil
}

func (s *Server) fail(c *gin.Context, code int, msg string) {
	c.JSON(code, gin.H{"error": gin.H{"message": msg}})
}

func atoi(s string, d int) int {
	if s == "" {
		return d
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return d
	}
	return n
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (s *Server) myLedger(c *gin.Context) {
	if c.GetBool("break_glass") || s.isAdmin(c) {
		s.writeLedger(c, 0)
		return
	}
	acc, ok := s.currentAccount(c)
	if !ok {
		s.fail(c, 401, "login required")
		return
	}
	s.writeLedger(c, acc.ID)
}

func (s *Server) adminListLedger(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		s.fail(c, 400, "bad id")
		return
	}
	s.writeLedger(c, id)
}

func (s *Server) writeLedger(c *gin.Context, accountID int64) {
	items, err := s.store.ListCreditLedger(c.Request.Context(), accountID, 50)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("ledger", "err", err)
		return
	}
	out := make([]gin.H, 0, len(items))
	for _, it := range items {
		out = append(out, gin.H{
			"id": it.ID, "account_id": it.AccountID, "delta": it.Delta,
			"delta_usd": float64(it.Delta) / float64(store.CreditScale),
			"balance":   it.Balance, "balance_usd": float64(it.Balance) / float64(store.CreditScale),
			"reason": it.Reason, "ref": it.Ref, "note": it.Note,
			"actor_id": it.ActorID, "created_at": it.CreatedAt,
		})
	}
	c.JSON(200, gin.H{"items": out})
}

func (s *Server) myCredits(c *gin.Context) {
	if c.GetBool("break_glass") {
		c.JSON(200, gin.H{"credits": int64(0), "credits_usd": 0, "break_glass": true})
		return
	}
	acc, ok := s.currentAccount(c)
	if !ok {
		s.fail(c, 401, "login required")
		return
	}
	fresh, err := s.store.GetAccount(c.Request.Context(), acc.ID)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	c.JSON(200, gin.H{"credits": fresh.Credits, "credits_usd": float64(fresh.Credits) / float64(store.CreditScale)})
}

func (s *Server) adminListAccounts(c *gin.Context) {
	items, err := s.store.ListAccounts(c.Request.Context())
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	out := make([]gin.H, 0, len(items))
	for _, a := range items {
		out = append(out, accountDTO(a))
	}
	c.JSON(200, gin.H{"items": out})
}

type creditReq struct {
	Delta int64  `json:"delta"`
	Note  string `json:"note"`
}

func (s *Server) adminAdjustCredits(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		s.fail(c, 400, "bad id")
		return
	}
	var req creditReq
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	if req.Delta == 0 || req.Delta > 1_000_000 || req.Delta < -1_000_000 {
		s.fail(c, 400, "调整额度须为 -1000000 到 1000000 之间的非 0 整数")
		return
	}
	// delta 单位是积分（美元），内部用微积分。
	micro := req.Delta * store.CreditScale
	var actorID *int64
	if acc, ok := s.currentAccount(c); ok {
		a := acc.ID
		actorID = &a
	}
	next, err := s.store.PostCredit(c.Request.Context(), id, micro, true, store.LedgerAdjust, "", clip(strings.TrimSpace(req.Note), 200), actorID)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(c, 404, "not found")
		return
	}
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	s.log.Info("credits adjusted", "account", id, "delta", req.Delta, "note", req.Note, "credits", next)
	c.JSON(200, gin.H{"id": id, "credits": next, "credits_usd": float64(next) / float64(store.CreditScale)})
}

func (s *Server) redeemCode(c *gin.Context) {
	if !s.allowAuth(c, "redeem", 8) {
		return
	}
	if c.GetBool("break_glass") {
		s.fail(c, 400, "应急口令没有账号，不能兑换积分")
		return
	}
	acc, ok := s.currentAccount(c)
	if !ok {
		s.fail(c, 401, "login required")
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	code := normalizeRedeem(req.Code)
	if code == "" {
		s.fail(c, 400, "请填写兑换码")
		return
	}
	added, next, err := s.store.RedeemCode(c.Request.Context(), cryptox.HashAPIKey(code), acc.ID)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(c, 404, "兑换码无效")
		return
	}
	if errors.Is(err, store.ErrRedeemUsed) {
		s.fail(c, 409, "兑换码已使用")
		return
	}
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	c.JSON(200, gin.H{
		"added": added, "added_usd": float64(added) / float64(store.CreditScale),
		"credits": next, "credits_usd": float64(next) / float64(store.CreditScale),
	})
}

type redeemBatchReq struct {
	Credits int64  `json:"credits"`
	Count   int    `json:"count"`
	Note    string `json:"note"`
}

func (s *Server) adminCreateRedeemCodes(c *gin.Context) {
	var req redeemBatchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	if req.Credits <= 0 || req.Credits > 1_000_000 {
		s.fail(c, 400, "面额须为 1 到 1000000 的整数积分")
		return
	}
	if req.Count < 1 || req.Count > 100 {
		s.fail(c, 400, "一次生成 1 到 100 个")
		return
	}
	note := clip(strings.TrimSpace(req.Note), 200)
	var createdBy *int64
	if acc, ok := s.currentAccount(c); ok {
		id := acc.ID
		createdBy = &id
	}
	plains := make([]string, 0, req.Count)
	items := make([]store.RedeemCode, 0, req.Count)
	seen := map[string]struct{}{}
	for len(plains) < req.Count {
		plain, err := newRedeemCode()
		if err != nil {
			s.fail(c, 500, "internal error")
			s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
			return
		}
		if _, ok := seen[plain]; ok {
			continue
		}
		seen[plain] = struct{}{}
		plains = append(plains, plain)
		items = append(items, store.RedeemCode{
			CodeHash: cryptox.HashAPIKey(plain), CodePrefix: plain[:9],
			Credits: req.Credits * store.CreditScale, Note: note, CreatedBy: createdBy,
		})
	}
	if err := s.store.InsertRedeemCodes(c.Request.Context(), items); err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	c.JSON(201, gin.H{"credits": req.Credits, "note": note, "codes": plains})
}

func (s *Server) adminListRedeemCodes(c *gin.Context) {
	items, err := s.store.ListRedeemCodes(c.Request.Context(), 100)
	if err != nil {
		s.fail(c, 500, "internal error")
		s.log.Error("request failed", "op", c.Request.Method+" "+c.FullPath(), "err", err)
		return
	}
	out := make([]gin.H, 0, len(items))
	for _, it := range items {
		out = append(out, gin.H{
			"id": it.ID, "prefix": it.CodePrefix,
			"credits": it.Credits, "credits_usd": float64(it.Credits) / float64(store.CreditScale),
			"note": it.Note, "created_by": it.CreatedBy, "redeemed_by": it.RedeemedBy,
			"redeemed_at": it.RedeemedAt, "created_at": it.CreatedAt,
		})
	}
	c.JSON(200, gin.H{"items": out})
}

func newRedeemCode() (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	raw := make([]byte, 12)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("RC-")
	for i, x := range raw {
		if i > 0 && i%4 == 0 {
			b.WriteByte('-')
		}
		b.WriteByte(alphabet[int(x)%len(alphabet)])
	}
	return b.String(), nil
}

func normalizeRedeem(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	compact := b.String()
	if !strings.HasPrefix(compact, "RC") || len(compact) != 14 {
		return ""
	}
	body := compact[2:]
	for _, r := range body {
		if (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return ""
		}
	}
	return "RC-" + body[:4] + "-" + body[4:8] + "-" + body[8:]
}
