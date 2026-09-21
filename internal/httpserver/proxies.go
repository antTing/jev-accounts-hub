package httpserver

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"jevproxy/internal/outproxy"
	"jevproxy/internal/store"
)

type optionalInt64 struct {
	set bool
	val *int64
}

func (o *optionalInt64) UnmarshalJSON(b []byte) error {
	o.set = true
	if string(b) == "null" {
		o.val = nil
		return nil
	}
	var v int64
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	o.val = &v
	return nil
}

func (s *Server) adminListProxies(c *gin.Context) {
	items, err := s.store.ListProxies(c.Request.Context())
	if err != nil {
		s.fail(c, 500, err.Error())
		return
	}
	out := make([]proxyDTO, 0, len(items))
	for _, p := range items {
		out = append(out, toProxyDTO(p))
	}
	c.JSON(200, gin.H{"items": out})
}

type proxyDTO struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Protocol      string `json:"protocol"`
	Host          string `json:"host"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	HasPassword   bool   `json:"has_password"`
	URL           string `json:"url"`
	Status        string `json:"status"`
	FailCount     int    `json:"fail_count"`
	CooldownUntil int64  `json:"cooldown_until"`
	LastOKAt      *int64 `json:"last_ok_at"`
	LastErrAt     *int64 `json:"last_err_at"`
	LastErr       string `json:"last_err"`
	LastIP        string `json:"last_ip"`
	LastCountry   string `json:"last_country"`
	LastLatencyMS int64  `json:"last_latency_ms"`
	BoundCount    int64  `json:"bound_count"`
	CreatedAt     int64  `json:"created_at"`
}

func toProxyDTO(p store.Proxy) proxyDTO {
	return proxyDTO{
		ID: p.ID, Name: p.Name, Protocol: p.Protocol, Host: p.Host, Port: p.Port,
		Username: p.Username, HasPassword: p.Password != "", URL: outproxy.Redacted(p),
		Status: p.Status, FailCount: p.FailCount, CooldownUntil: p.CooldownUntil,
		LastOKAt: p.LastOKAt, LastErrAt: p.LastErrAt, LastErr: p.LastErr,
		LastIP: p.LastIP, LastCountry: p.LastCountry, LastLatencyMS: p.LastLatencyMS,
		BoundCount: p.BoundCount, CreatedAt: p.CreatedAt,
	}
}

type proxyReq struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Status   string `json:"status"`
}

func (s *Server) parseProxyReq(req proxyReq, cur *store.Proxy) (store.Proxy, error) {
	var p store.Proxy
	if u := strings.TrimSpace(req.URL); u != "" {
		parsed, err := outproxy.Parse(u)
		if err != nil {
			return store.Proxy{}, err
		}
		p = parsed
	} else if cur != nil {
		p = *cur
		if req.Protocol != "" {
			p.Protocol = req.Protocol
		}
		if req.Host != "" {
			p.Host = req.Host
		}
		if req.Port != 0 {
			p.Port = req.Port
		}
		if req.Username != "" || req.Protocol != "" || req.Host != "" {
			p.Username = req.Username
		}
		if req.Password != "" {
			p.Password = req.Password
		}
	} else {
		p = store.Proxy{
			Protocol: req.Protocol,
			Host:     req.Host,
			Port:     req.Port,
			Username: req.Username,
			Password: req.Password,
		}
	}
	if n := strings.TrimSpace(req.Name); n != "" {
		p.Name = n
	}
	if req.Status != "" {
		p.Status = req.Status
	}
	if err := outproxy.Normalize(&p); err != nil {
		return store.Proxy{}, err
	}
	return p, nil
}

func (s *Server) adminCreateProxy(c *gin.Context) {
	var req proxyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	p, err := s.parseProxyReq(req, nil)
	if err != nil {
		s.fail(c, 400, err.Error())
		return
	}
	id, err := s.store.InsertProxy(c.Request.Context(), p)
	if err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.fail(c, 409, "proxy already exists")
			return
		}
		s.fail(c, 500, err.Error())
		return
	}
	got, err := s.store.GetProxy(c.Request.Context(), id)
	if err != nil {
		s.fail(c, 500, err.Error())
		return
	}
	c.JSON(201, toProxyDTO(got))
}

func (s *Server) adminUpdateProxy(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		s.fail(c, 400, "bad id")
		return
	}
	cur, err := s.store.GetProxy(c.Request.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(c, 404, "not found")
		return
	}
	if err != nil {
		s.fail(c, 500, err.Error())
		return
	}
	var req proxyReq
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	p, err := s.parseProxyReq(req, &cur)
	if err != nil {
		s.fail(c, 400, err.Error())
		return
	}
	if err := s.store.UpdateProxy(c.Request.Context(), id, p.Name, p.Protocol, p.Host, p.Port, p.Username, p.Password, p.Status); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.fail(c, 409, "proxy already exists")
			return
		}
		s.fail(c, 500, err.Error())
		return
	}
	got, _ := s.store.GetProxy(c.Request.Context(), id)
	c.JSON(200, toProxyDTO(got))
}

func (s *Server) adminDeleteProxy(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		s.fail(c, 400, "bad id")
		return
	}
	if err := s.store.DeleteProxy(c.Request.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.fail(c, 404, "not found")
			return
		}
		s.fail(c, 500, err.Error())
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

func (s *Server) adminProbeProxy(c *gin.Context) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		s.fail(c, 400, "bad id")
		return
	}
	p, err := s.store.GetProxy(c.Request.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.fail(c, 404, "not found")
		return
	}
	if err != nil {
		s.fail(c, 500, err.Error())
		return
	}
	res := outproxy.Probe(c.Request.Context(), p, 10*time.Second)
	if res.OK {
		_ = s.store.TouchProxyOK(c.Request.Context(), id, res.IP, res.Country, res.LatencyMS)
	} else {
		_ = s.store.TouchProxyErr(c.Request.Context(), id, res.Error, outproxy.CooldownMS())
	}
	c.JSON(200, gin.H{
		"ok":         res.OK,
		"latency_ms": res.LatencyMS,
		"ip":         res.IP,
		"country":    res.Country,
		"error":      res.Error,
	})
}

type proxyImportReq struct {
	Text string `json:"text"`
}

func (s *Server) adminImportProxies(c *gin.Context) {
	var req proxyImportReq
	if err := c.ShouldBindJSON(&req); err != nil {
		s.fail(c, 400, "invalid json")
		return
	}
	created, skipped, failed := 0, 0, 0
	var items []proxyDTO
	var errs []string
	for _, raw := range strings.Split(req.Text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p, err := outproxy.ParseLine(line)
		if err != nil {
			failed++
			if len(errs) < 8 {
				errs = append(errs, line+": "+err.Error())
			}
			continue
		}
		id, err := s.store.InsertProxy(c.Request.Context(), p)
		if err != nil {
			if errors.Is(err, store.ErrConflict) {
				skipped++
				continue
			}
			s.fail(c, 500, err.Error())
			return
		}
		got, _ := s.store.GetProxy(c.Request.Context(), id)
		items = append(items, toProxyDTO(got))
		created++
	}
	if created == 0 && skipped == 0 && failed == 0 {
		s.fail(c, 400, "no proxies found")
		return
	}
	c.JSON(201, gin.H{"created": created, "skipped": skipped, "failed": failed, "errors": errs, "items": items})
}
