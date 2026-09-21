package httpserver

import (
	"context"
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

	"github.com/gin-contrib/cors"
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
	Listen     string
	AdminToken string
	Debug      bool
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
	r.Use(cors.New(cors.Config{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-Id", "X-Admin-Token"},
		ExposeHeaders:    []string{"X-Request-Id", "Retry-After"},
		AllowCredentials: false,
		MaxAge:           12 * time.Hour,
	}))

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})

	v1 := r.Group("/v1")
	v1.POST("/systemone", s.handleSystemOne)
	v1.GET("/models", s.handleModels)

	admin := r.Group("/admin/api")
	admin.Use(s.requireAdmin())
	admin.GET("/stats", s.adminStats)
	admin.GET("/upstreams", s.adminListUpstreams)
	admin.POST("/upstreams", s.adminCreateUpstream)
	admin.POST("/upstreams/import", s.adminImportUpstreams)
	admin.POST("/upstreams/probe-all", s.adminProbeAll)
	admin.PUT("/upstreams/:id", s.adminUpdateUpstream)
	admin.DELETE("/upstreams/:id", s.adminDeleteUpstream)
	admin.POST("/upstreams/:id/probe", s.adminProbeUpstream)
	admin.GET("/keys", s.adminListKeys)
	admin.POST("/keys", s.adminCreateKey)
	admin.PUT("/keys/:id", s.adminUpdateKey)
	admin.DELETE("/keys/:id", s.adminDeleteKey)
	admin.POST("/keys/:id/reset-usage", s.adminResetKeyUsage)
	admin.GET("/logs", s.adminLogs)
	admin.POST("/playground", s.adminPlayground)

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

func (s *Server) requireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		tok := c.GetHeader("X-Admin-Token")
		if tok == "" {
			if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
				tok = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
			}
		}
		if !cryptox.EqualToken(strings.TrimSpace(tok), strings.TrimSpace(s.cfg.AdminToken)) {
			c.AbortWithStatusJSON(401, gin.H{"error": gin.H{"type": "unauthorized", "message": "invalid admin token"}})
			return
		}
		c.Next()
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
	st, err := s.store.Stats(c.Request.Context())
	if err != nil {
		s.fail(c, 500, err.Error())
		return
	}
	c.JSON(200, st)
}

type upstreamDTO struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Mask          string `json:"mask"`
	Weight        int    `json:"weight"`
	RPMLimit      int    `json:"rpm_limit"`
	Status        string `json:"status"`
	FailCount     int    `json:"fail_count"`
	CooldownUntil int64  `json:"cooldown_until"`
	LastOKAt      *int64 `json:"last_ok_at"`
	LastErrAt     *int64 `json:"last_err_at"`
	LastErr       string `json:"last_err"`
	CreatedAt     int64  `json:"created_at"`
}

func toUpstreamDTO(u store.Upstream) upstreamDTO {
	return upstreamDTO{
		ID: u.ID, Name: u.Name, Mask: u.Mask(), Weight: u.Weight, RPMLimit: u.RPMLimit,
		Status: u.Status, FailCount: u.FailCount, CooldownUntil: u.CooldownUntil,
		LastOKAt: u.LastOKAt, LastErrAt: u.LastErrAt, LastErr: u.LastErr, CreatedAt: u.CreatedAt,
	}
}

func (s *Server) adminListUpstreams(c *gin.Context) {
	items, err := s.store.ListUpstreams(c.Request.Context())
	if err != nil {
		s.fail(c, 500, err.Error())
		return
	}
	out := make([]upstreamDTO, 0, len(items))
	for _, u := range items {
		out = append(out, toUpstreamDTO(u))
	}
	c.JSON(200, gin.H{"items": out})
}

type upstreamReq struct {
	Name     string `json:"name"`
	APIKey   string `json:"api_key"`
	Weight   *int   `json:"weight"`
	RPMLimit *int   `json:"rpm_limit"`
	Status   string `json:"status"`
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
	u, err := s.insertUpstream(c.Request.Context(), strings.TrimSpace(req.Name), key, weight, rpm, req.Status)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.fail(c, 409, "upstream key already imported")
			return
		}
		s.fail(c, 500, err.Error())
		return
	}
	c.JSON(201, toUpstreamDTO(u))
}

func (s *Server) insertUpstream(ctx context.Context, name, key string, weight, rpm int, status string) (store.Upstream, error) {
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
		Weight: weight, RPMLimit: rpm, Status: status,
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
		s.fail(c, 500, err.Error())
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
			s.fail(c, 500, err.Error())
			return
		}
		prefix, last4 = store.PrefixLast4(k)
		hash = cryptox.HashAPIKey(k)
	}
	if err := s.store.UpdateUpstream(c.Request.Context(), id, name, weight, rpm, status, enc, prefix, last4, hash); err != nil {
		s.fail(c, 500, err.Error())
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
		s.fail(c, 500, err.Error())
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
		s.fail(c, 500, err.Error())
		return
	}
	key, err := s.pool.Decrypt(u)
	if err != nil {
		s.fail(c, 500, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 12*time.Second)
	defer cancel()
	status, body, ferr := s.gw.Probe(ctx, key)
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
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Mask       string `json:"mask"`
	RPMLimit   int    `json:"rpm_limit"`
	TokenQuota int64  `json:"token_quota"`
	TokensUsed int64  `json:"tokens_used"`
	Status     string `json:"status"`
	Note       string `json:"note"`
	ExpiresAt  *int64 `json:"expires_at"`
	LastUsedAt *int64 `json:"last_used_at"`
	CreatedAt  int64  `json:"created_at"`
	Plain      string `json:"plain,omitempty"`
}

func toUserDTO(k store.UserKey) userKeyDTO {
	return userKeyDTO{
		ID: k.ID, Name: k.Name, Mask: k.Mask(), RPMLimit: k.RPMLimit,
		TokenQuota: k.TokenQuota, TokensUsed: k.TokensUsed, Status: k.Status, Note: k.Note,
		ExpiresAt: k.ExpiresAt, LastUsedAt: k.LastUsedAt, CreatedAt: k.CreatedAt,
	}
}

func (s *Server) adminListKeys(c *gin.Context) {
	items, err := s.store.ListUserKeys(c.Request.Context())
	if err != nil {
		s.fail(c, 500, err.Error())
		return
	}
	out := make([]userKeyDTO, 0, len(items))
	for _, k := range items {
		out = append(out, toUserDTO(k))
	}
	c.JSON(200, gin.H{"items": out})
}

type keyReq struct {
	Name       string  `json:"name"`
	RPMLimit   *int    `json:"rpm_limit"`
	TokenQuota *int64  `json:"token_quota"`
	Status     string  `json:"status"`
	Note       *string `json:"note"`
	ExpiresAt  *int64  `json:"expires_at"`
}

func (s *Server) adminCreateKey(c *gin.Context) {
	var req keyReq
	if err := c.ShouldBindJSON(&req); err != nil && !errors.Is(err, io.EOF) {
		s.fail(c, 400, "invalid json")
		return
	}
	body, err := cryptox.RandomString(40)
	if err != nil {
		s.fail(c, 500, err.Error())
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
	var quota int64
	if req.TokenQuota != nil {
		quota = *req.TokenQuota
	}
	note := ""
	if req.Note != nil {
		note = strings.TrimSpace(*req.Note)
	}
	id, err := s.store.InsertUserKey(c.Request.Context(), store.UserKey{
		Name: name, KeyHash: cryptox.HashAPIKey(plain), KeyPrefix: prefix, KeyLast4: last4,
		RPMLimit: rpm, TokenQuota: quota, Status: "active", Note: note, ExpiresAt: req.ExpiresAt,
	})
	if err != nil {
		s.fail(c, 500, err.Error())
		return
	}
	k, _ := s.store.GetUserKey(c.Request.Context(), id)
	dto := toUserDTO(k)
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
		s.fail(c, 500, err.Error())
		return
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
	quota := cur.TokenQuota
	if req.TokenQuota != nil {
		quota = *req.TokenQuota
	}
	note := cur.Note
	if req.Note != nil {
		note = *req.Note
	}
	exp := cur.ExpiresAt
	if req.ExpiresAt != nil {
		exp = req.ExpiresAt
	}
	if err := s.store.UpdateUserKey(c.Request.Context(), id, name, rpm, quota, status, exp, note); err != nil {
		s.fail(c, 500, err.Error())
		return
	}
	k, _ := s.store.GetUserKey(c.Request.Context(), id)
	c.JSON(200, toUserDTO(k))
}

func (s *Server) adminDeleteKey(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		s.fail(c, 400, "bad id")
		return
	}
	if err := s.store.DeleteUserKey(c.Request.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(c, 404, "not found")
			return
		}
		s.fail(c, 500, err.Error())
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
	if err := s.store.ResetTokens(c.Request.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(c, 404, "not found")
			return
		}
		s.fail(c, 500, err.Error())
		return
	}
	k, _ := s.store.GetUserKey(c.Request.Context(), id)
	c.JSON(200, toUserDTO(k))
}

func (s *Server) adminLogs(c *gin.Context) {
	f := store.LogFilter{Limit: atoi(c.Query("limit"), 50), Offset: atoi(c.Query("offset"), 0), Q: c.Query("q")}
	if v := c.Query("user_key_id"); v != "" {
		f.UserKeyID, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := c.Query("upstream_id"); v != "" {
		f.UpstreamID, _ = strconv.ParseInt(v, 10, 64)
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
		s.fail(c, 500, err.Error())
		return
	}
	c.JSON(200, gin.H{"items": items, "total": total, "limit": f.Limit, "offset": f.Offset})
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
		u, err := s.insertUpstream(c.Request.Context(), ln.name, ln.key, req.Weight, req.RPMLimit, "active")
		if err != nil {
			if errors.Is(err, store.ErrConflict) {
				skipped++
				continue
			}
			s.fail(c, 500, err.Error())
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
		s.fail(c, 500, err.Error())
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
		status, body, ferr := s.gw.Probe(ctx, key)
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
	res := s.gw.Evaluate(c.Request.Context(), nil, body, c.GetString("request_id"))
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
		"raw":           string(res.Body),
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
