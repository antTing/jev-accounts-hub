package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type Store struct {
	db *sql.DB
}

func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(filepath.Join(dataDir, "jevproxy.db"))
	if err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", filepath.ToSlash(abs))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS upstream_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  key_enc BLOB NOT NULL,
  key_prefix TEXT NOT NULL,
  key_last4 TEXT NOT NULL,
  weight INTEGER NOT NULL DEFAULT 1,
  rpm_limit INTEGER NOT NULL DEFAULT 1000,
  status TEXT NOT NULL DEFAULT 'active',
  fail_count INTEGER NOT NULL DEFAULT 0,
  cooldown_until INTEGER NOT NULL DEFAULT 0,
  last_ok_at INTEGER,
  last_err_at INTEGER,
  last_err TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_keys (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  key_last4 TEXT NOT NULL,
  rpm_limit INTEGER NOT NULL DEFAULT 60,
  token_quota INTEGER NOT NULL DEFAULT 0,
  tokens_used INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active',
  expires_at INTEGER,
  last_used_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS usage_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_key_id INTEGER NOT NULL,
  upstream_id INTEGER,
  model TEXT,
  input_tokens INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  latency_ms INTEGER NOT NULL DEFAULT 0,
  status_code INTEGER NOT NULL,
  ok INTEGER NOT NULL,
  error TEXT,
  request_id TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_usage_created ON usage_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_usage_user ON usage_logs(user_key_id, created_at DESC);

CREATE TABLE IF NOT EXISTS proxies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  protocol TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  username TEXT NOT NULL DEFAULT '',
  password TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'active',
  fail_count INTEGER NOT NULL DEFAULT 0,
  cooldown_until INTEGER NOT NULL DEFAULT 0,
  last_ok_at INTEGER,
  last_err_at INTEGER,
  last_err TEXT,
  last_ip TEXT NOT NULL DEFAULT '',
  last_country TEXT NOT NULL DEFAULT '',
  last_latency_ms INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_proxy_endpoint ON proxies(protocol, host, port, username, password);
CREATE INDEX IF NOT EXISTS idx_proxy_status ON proxies(status);
`)
	if err != nil {
		return err
	}
	return s.ensureColumns()
}

func (s *Store) ensureColumns() error {
	if err := s.addColumnIfMissing("user_keys", "note", `ALTER TABLE user_keys ADD COLUMN note TEXT NOT NULL DEFAULT ''`); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("upstream_keys", "key_hash", `ALTER TABLE upstream_keys ADD COLUMN key_hash TEXT`); err != nil {
		return err
	}
	if err := s.addColumnIfMissing("upstream_keys", "proxy_id", `ALTER TABLE upstream_keys ADD COLUMN proxy_id INTEGER`); err != nil {
		return err
	}
	_, err := s.db.Exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_upstream_key_hash ON upstream_keys(key_hash) WHERE key_hash IS NOT NULL AND key_hash != ''`)
	return err
}

func (s *Store) addColumnIfMissing(table, col, ddl string) error {
	var n int
	q := `SELECT COUNT(*) FROM pragma_table_info('` + table + `') WHERE name=?`
	if err := s.db.QueryRow(q, col).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := s.db.Exec(ddl); err != nil {
			return err
		}
	}
	return nil
}

func nowMS() int64 { return time.Now().UnixMilli() }

// ProxyID 语义：
//
//	nil = 走共享代理池（池空则直连）
//	0   = 强制直连
//	N   = 固定绑定代理 N
type Upstream struct {
	ID            int64
	Name          string
	KeyEnc        []byte
	KeyPrefix     string
	KeyLast4      string
	Weight        int
	RPMLimit      int
	Status        string
	FailCount     int
	CooldownUntil int64
	LastOKAt      *int64
	LastErrAt     *int64
	LastErr       string
	CreatedAt     int64
	UpdatedAt     int64
	KeyHash       string
	ProxyID       *int64
}

type Proxy struct {
	ID            int64
	Name          string
	Protocol      string
	Host          string
	Port          int
	Username      string
	Password      string
	Status        string
	FailCount     int
	CooldownUntil int64
	LastOKAt      *int64
	LastErrAt     *int64
	LastErr       string
	LastIP        string
	LastCountry   string
	LastLatencyMS int64
	CreatedAt     int64
	UpdatedAt     int64
	BoundCount    int64
}

func (u Upstream) Mask() string {
	p := u.KeyPrefix
	if p == "" {
		p = "jev_"
	}
	return p + "****" + u.KeyLast4
}

type UserKey struct {
	ID         int64
	Name       string
	KeyHash    string
	KeyPrefix  string
	KeyLast4   string
	RPMLimit   int
	TokenQuota int64
	TokensUsed int64
	Status     string
	ExpiresAt  *int64
	LastUsedAt *int64
	Note       string
	CreatedAt  int64
	UpdatedAt  int64
}

func (k UserKey) Mask() string {
	return k.KeyPrefix + "****" + k.KeyLast4
}

func (k UserKey) Active() bool {
	if k.Status != "active" {
		return false
	}
	if k.ExpiresAt != nil && nowMS() > *k.ExpiresAt {
		return false
	}
	return true
}

type UsageLog struct {
	ID           int64  `json:"id"`
	UserKeyID    int64  `json:"user_key_id"`
	UpstreamID   *int64 `json:"upstream_id"`
	Model        string `json:"model"`
	InputTokens  int64  `json:"input_tokens"`
	OutputTokens int64  `json:"output_tokens"`
	LatencyMS    int64  `json:"latency_ms"`
	StatusCode   int    `json:"status_code"`
	OK           bool   `json:"ok"`
	Error        string `json:"error"`
	RequestID    string `json:"request_id"`
	CreatedAt    int64  `json:"created_at"`
}

const upstreamCols = `id,name,key_enc,key_prefix,key_last4,weight,rpm_limit,status,fail_count,cooldown_until,last_ok_at,last_err_at,last_err,created_at,updated_at,proxy_id`

func (s *Store) ListUpstreams(ctx context.Context) ([]Upstream, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+upstreamCols+` FROM upstream_keys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Upstream
	for rows.Next() {
		u, err := scanUpstream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

type UpstreamUsage struct {
	InputTokens int64
	Requests    int64
}

func (s *Store) UpstreamUsage(ctx context.Context) (map[int64]UpstreamUsage, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT upstream_id, COALESCE(SUM(input_tokens),0), COUNT(*) FROM usage_logs WHERE upstream_id IS NOT NULL AND ok=1 GROUP BY upstream_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]UpstreamUsage{}
	for rows.Next() {
		var id int64
		var u UpstreamUsage
		if err := rows.Scan(&id, &u.InputTokens, &u.Requests); err != nil {
			return nil, err
		}
		out[id] = u
	}
	return out, rows.Err()
}

func (s *Store) GetUpstream(ctx context.Context, id int64) (Upstream, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+upstreamCols+` FROM upstream_keys WHERE id=?`, id)
	u, err := scanUpstream(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Upstream{}, ErrNotFound
	}
	return u, err
}

func (s *Store) InsertUpstream(ctx context.Context, u Upstream) (int64, error) {
	now := nowMS()
	var hash any
	if h := strings.TrimSpace(u.KeyHash); h != "" {
		hash = h
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO upstream_keys(name,key_enc,key_prefix,key_last4,weight,rpm_limit,status,fail_count,cooldown_until,created_at,updated_at,key_hash,proxy_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		u.Name, u.KeyEnc, u.KeyPrefix, u.KeyLast4, nz(u.Weight, 1), nz(u.RPMLimit, 1000), nstr(u.Status, "active"), 0, 0, now, now, hash, nullInt(u.ProxyID))
	if err != nil {
		if strings.Contains(strings.ToUpper(err.Error()), "UNIQUE") {
			return 0, ErrConflict
		}
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpstreamHashExists(ctx context.Context, hash string) (bool, error) {
	if strings.TrimSpace(hash) == "" {
		return false, nil
	}
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream_keys WHERE key_hash=?`, hash).Scan(&n)
	return n > 0, err
}

func (s *Store) UpdateUpstream(ctx context.Context, id int64, name string, weight, rpm int, status string, keyEnc []byte, prefix, last4, keyHash string, proxyID *int64, setProxy bool) error {
	now := nowMS()
	var res sql.Result
	var err error
	if keyEnc != nil {
		var hash any
		if h := strings.TrimSpace(keyHash); h != "" {
			hash = h
		}
		if setProxy {
			res, err = s.db.ExecContext(ctx, `UPDATE upstream_keys SET name=?, weight=?, rpm_limit=?, status=?, key_enc=?, key_prefix=?, key_last4=?, key_hash=?, proxy_id=?, updated_at=? WHERE id=?`,
				name, nz(weight, 1), nz(rpm, 1000), nstr(status, "active"), keyEnc, prefix, last4, hash, nullInt(proxyID), now, id)
		} else {
			res, err = s.db.ExecContext(ctx, `UPDATE upstream_keys SET name=?, weight=?, rpm_limit=?, status=?, key_enc=?, key_prefix=?, key_last4=?, key_hash=?, updated_at=? WHERE id=?`,
				name, nz(weight, 1), nz(rpm, 1000), nstr(status, "active"), keyEnc, prefix, last4, hash, now, id)
		}
	} else if setProxy {
		res, err = s.db.ExecContext(ctx, `UPDATE upstream_keys SET name=?, weight=?, rpm_limit=?, status=?, proxy_id=?, updated_at=? WHERE id=?`,
			name, nz(weight, 1), nz(rpm, 1000), nstr(status, "active"), nullInt(proxyID), now, id)
	} else {
		res, err = s.db.ExecContext(ctx, `UPDATE upstream_keys SET name=?, weight=?, rpm_limit=?, status=?, updated_at=? WHERE id=?`,
			name, nz(weight, 1), nz(rpm, 1000), nstr(status, "active"), now, id)
	}
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteUpstream(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM upstream_keys WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) TouchUpstreamOK(ctx context.Context, id int64) error {
	now := nowMS()
	_, err := s.db.ExecContext(ctx, `UPDATE upstream_keys SET fail_count=0, cooldown_until=0, last_ok_at=?, updated_at=? WHERE id=?`, now, now, id)
	return err
}

func (s *Store) TouchUpstreamErr(ctx context.Context, id int64, msg string, cooldownMS int64, authFail bool) error {
	now := nowMS()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	inc := 1
	if authFail {
		inc = 5
	}
	_, err := s.db.ExecContext(ctx, `UPDATE upstream_keys SET fail_count=fail_count+?, cooldown_until=?, last_err_at=?, last_err=?, updated_at=? WHERE id=?`,
		inc, cooldownMS, now, msg, now, id)
	return err
}

func (s *Store) InsertUserKey(ctx context.Context, k UserKey) (int64, error) {
	now := nowMS()
	res, err := s.db.ExecContext(ctx, `INSERT INTO user_keys(name,key_hash,key_prefix,key_last4,rpm_limit,token_quota,tokens_used,status,expires_at,note,created_at,updated_at) VALUES(?,?,?,?,?,?,0,?,?,?,?,?)`,
		k.Name, k.KeyHash, k.KeyPrefix, k.KeyLast4, nz(k.RPMLimit, 60), k.TokenQuota, nstr(k.Status, "active"), k.ExpiresAt, k.Note, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, ErrConflict
		}
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListUserKeys(ctx context.Context) ([]UserKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,key_hash,key_prefix,key_last4,rpm_limit,token_quota,tokens_used,status,expires_at,last_used_at,note,created_at,updated_at FROM user_keys ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserKey
	for rows.Next() {
		k, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) GetUserKey(ctx context.Context, id int64) (UserKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,key_hash,key_prefix,key_last4,rpm_limit,token_quota,tokens_used,status,expires_at,last_used_at,note,created_at,updated_at FROM user_keys WHERE id=?`, id)
	k, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return UserKey{}, ErrNotFound
	}
	return k, err
}

func (s *Store) LookupUserKey(ctx context.Context, hash string) (UserKey, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,key_hash,key_prefix,key_last4,rpm_limit,token_quota,tokens_used,status,expires_at,last_used_at,note,created_at,updated_at FROM user_keys WHERE key_hash=?`, hash)
	k, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return UserKey{}, ErrNotFound
	}
	return k, err
}

func (s *Store) UpdateUserKey(ctx context.Context, id int64, name string, rpm int, quota int64, status string, expiresAt *int64, note string) error {
	now := nowMS()
	res, err := s.db.ExecContext(ctx, `UPDATE user_keys SET name=?, rpm_limit=?, token_quota=?, status=?, expires_at=?, note=?, updated_at=? WHERE id=?`,
		name, nz(rpm, 60), quota, nstr(status, "active"), expiresAt, note, now, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteUserKey(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM user_keys WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) AddTokens(ctx context.Context, id int64, n int64) error {
	now := nowMS()
	_, err := s.db.ExecContext(ctx, `UPDATE user_keys SET tokens_used=tokens_used+?, last_used_at=?, updated_at=? WHERE id=?`, n, now, now, id)
	return err
}

func (s *Store) ResetTokens(ctx context.Context, id int64) error {
	now := nowMS()
	res, err := s.db.ExecContext(ctx, `UPDATE user_keys SET tokens_used=0, updated_at=? WHERE id=?`, now, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) InsertLog(ctx context.Context, l UsageLog) error {
	ok := 0
	if l.OK {
		ok = 1
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO usage_logs(user_key_id,upstream_id,model,input_tokens,output_tokens,latency_ms,status_code,ok,error,request_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		l.UserKeyID, l.UpstreamID, l.Model, l.InputTokens, l.OutputTokens, l.LatencyMS, l.StatusCode, ok, l.Error, l.RequestID, nowMS())
	return err
}

type LogFilter struct {
	UserKeyID  int64
	UpstreamID int64
	OK         *bool
	Q          string
	Since      int64
	Limit      int
	Offset     int
}

func (s *Store) ListLogs(ctx context.Context, f LogFilter) ([]UsageLog, int64, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	where := []string{"1=1"}
	args := []any{}
	if f.UserKeyID > 0 {
		where = append(where, "user_key_id=?")
		args = append(args, f.UserKeyID)
	}
	if f.UpstreamID > 0 {
		where = append(where, "upstream_id=?")
		args = append(args, f.UpstreamID)
	}
	if f.Since > 0 {
		where = append(where, "created_at>=?")
		args = append(args, f.Since)
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		where = append(where, "(IFNULL(error,'') LIKE ? OR IFNULL(model,'') LIKE ? OR IFNULL(request_id,'') LIKE ?)")
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	if f.OK != nil {
		v := 0
		if *f.OK {
			v = 1
		}
		where = append(where, "ok=?")
		args = append(args, v)
	}
	w := strings.Join(where, " AND ")
	var total int64
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM usage_logs WHERE "+w, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	qargs := append(append([]any{}, args...), f.Limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, `SELECT id,user_key_id,upstream_id,model,input_tokens,output_tokens,latency_ms,status_code,ok,error,request_id,created_at FROM usage_logs WHERE `+w+` ORDER BY id DESC LIMIT ? OFFSET ?`, qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []UsageLog
	for rows.Next() {
		var l UsageLog
		var up sql.NullInt64
		var ok int
		if err := rows.Scan(&l.ID, &l.UserKeyID, &up, &l.Model, &l.InputTokens, &l.OutputTokens, &l.LatencyMS, &l.StatusCode, &ok, &l.Error, &l.RequestID, &l.CreatedAt); err != nil {
			return nil, 0, err
		}
		if up.Valid {
			v := up.Int64
			l.UpstreamID = &v
		}
		l.OK = ok == 1
		out = append(out, l)
	}
	return out, total, rows.Err()
}

type HourPoint struct {
	T      int64   `json:"t"`
	Req    int64   `json:"req"`
	OK     int64   `json:"ok"`
	Tokens int64   `json:"tokens"`
	AvgMS  float64 `json:"avg_ms"`
}

type TopKey struct {
	UserKeyID int64  `json:"user_key_id"`
	Name      string `json:"name"`
	Mask      string `json:"mask"`
	Req       int64  `json:"req"`
	Tokens    int64  `json:"tokens"`
}

type Stats struct {
	Upstreams     int64       `json:"upstreams"`
	UpstreamsLive int64       `json:"upstreams_live"`
	UpstreamsCool int64       `json:"upstreams_cool"`
	UserKeys      int64       `json:"user_keys"`
	UserKeysLive  int64       `json:"user_keys_live"`
	Proxies       int64       `json:"proxies"`
	ProxiesLive   int64       `json:"proxies_live"`
	Req24h        int64       `json:"req_24h"`
	OK24h         int64       `json:"ok_24h"`
	Fail24h       int64       `json:"fail_24h"`
	Tokens24h     int64       `json:"tokens_24h"`
	ReqTotal      int64       `json:"req_total"`
	TokensTotal   int64       `json:"tokens_total"`
	LatencyP50    int64       `json:"latency_p50"`
	LatencyP95    int64       `json:"latency_p95"`
	Hourly        []HourPoint `json:"hourly"`
	TopKeys       []TopKey    `json:"top_keys"`
}

func (s *Store) Stats(ctx context.Context) (Stats, error) {
	var st Stats
	st.Hourly = []HourPoint{}
	st.TopKeys = []TopKey{}
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream_keys`).Scan(&st.Upstreams)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream_keys WHERE status='active'`).Scan(&st.UpstreamsLive)
	now := nowMS()
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM upstream_keys WHERE status='active' AND cooldown_until>?`, now).Scan(&st.UpstreamsCool)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_keys`).Scan(&st.UserKeys)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_keys WHERE status='active'`).Scan(&st.UserKeysLive)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM proxies`).Scan(&st.Proxies)
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM proxies WHERE status='active'`).Scan(&st.ProxiesLive)
	since := time.Now().Add(-24 * time.Hour).UnixMilli()
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(ok),0), COALESCE(SUM(input_tokens),0) FROM usage_logs WHERE created_at>=?`, since).Scan(&st.Req24h, &st.OK24h, &st.Tokens24h)
	st.Fail24h = st.Req24h - st.OK24h
	if st.Fail24h < 0 {
		st.Fail24h = 0
	}
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(input_tokens),0) FROM usage_logs`).Scan(&st.ReqTotal, &st.TokensTotal)

	rows, err := s.db.QueryContext(ctx, `SELECT latency_ms FROM usage_logs WHERE created_at>=? AND ok=1 ORDER BY latency_ms`, since)
	if err == nil {
		var lats []int64
		for rows.Next() {
			var v int64
			if rows.Scan(&v) == nil {
				lats = append(lats, v)
			}
		}
		_ = rows.Close()
		st.LatencyP50 = percentile(lats, 50)
		st.LatencyP95 = percentile(lats, 95)
	}

	hrows, err := s.db.QueryContext(ctx, `SELECT (created_at/3600000)*3600000 AS b, COUNT(*), COALESCE(SUM(ok),0), COALESCE(SUM(input_tokens),0), COALESCE(AVG(latency_ms),0) FROM usage_logs WHERE created_at>=? GROUP BY b ORDER BY b`, since)
	if err == nil {
		defer hrows.Close()
		for hrows.Next() {
			var hp HourPoint
			if hrows.Scan(&hp.T, &hp.Req, &hp.OK, &hp.Tokens, &hp.AvgMS) == nil {
				st.Hourly = append(st.Hourly, hp)
			}
		}
	}

	trows, err := s.db.QueryContext(ctx, `SELECT l.user_key_id, k.name, k.key_prefix, k.key_last4, COUNT(*), COALESCE(SUM(l.input_tokens),0)
FROM usage_logs l LEFT JOIN user_keys k ON k.id=l.user_key_id
WHERE l.created_at>=? GROUP BY l.user_key_id ORDER BY COUNT(*) DESC LIMIT 5`, since)
	if err == nil {
		defer trows.Close()
		for trows.Next() {
			var tk TopKey
			var prefix, last4 string
			if trows.Scan(&tk.UserKeyID, &tk.Name, &prefix, &last4, &tk.Req, &tk.Tokens) == nil {
				tk.Mask = prefix + "****" + last4
				st.TopKeys = append(st.TopKeys, tk)
			}
		}
	}
	return st, nil
}

const proxyCols = `id,name,protocol,host,port,username,password,status,fail_count,cooldown_until,last_ok_at,last_err_at,last_err,last_ip,last_country,last_latency_ms,created_at,updated_at`

func (s *Store) ListProxies(ctx context.Context) ([]Proxy, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+proxyCols+`, (SELECT COUNT(*) FROM upstream_keys u WHERE u.proxy_id=p.id) FROM proxies p ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Proxy
	for rows.Next() {
		p, err := scanProxy(rows, true)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) ListActiveProxies(ctx context.Context) ([]Proxy, error) {
	now := nowMS()
	rows, err := s.db.QueryContext(ctx, `SELECT `+proxyCols+` FROM proxies WHERE status='active' AND cooldown_until<=? ORDER BY id`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Proxy
	for rows.Next() {
		p, err := scanProxy(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetProxy(ctx context.Context, id int64) (Proxy, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+proxyCols+`, (SELECT COUNT(*) FROM upstream_keys u WHERE u.proxy_id=p.id) FROM proxies p WHERE p.id=?`, id)
	p, err := scanProxy(row, true)
	if errors.Is(err, sql.ErrNoRows) {
		return Proxy{}, ErrNotFound
	}
	return p, err
}

func (s *Store) InsertProxy(ctx context.Context, p Proxy) (int64, error) {
	now := nowMS()
	res, err := s.db.ExecContext(ctx, `INSERT INTO proxies(name,protocol,host,port,username,password,status,fail_count,cooldown_until,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,0,?,?)`,
		p.Name, p.Protocol, p.Host, p.Port, p.Username, p.Password, nstr(p.Status, "active"), 0, now, now)
	if err != nil {
		if strings.Contains(strings.ToUpper(err.Error()), "UNIQUE") {
			return 0, ErrConflict
		}
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateProxy(ctx context.Context, id int64, name, protocol, host string, port int, username, password, status string) error {
	now := nowMS()
	res, err := s.db.ExecContext(ctx, `UPDATE proxies SET name=?, protocol=?, host=?, port=?, username=?, password=?, status=?, updated_at=? WHERE id=?`,
		name, protocol, host, port, username, password, nstr(status, "active"), now, id)
	if err != nil {
		if strings.Contains(strings.ToUpper(err.Error()), "UNIQUE") {
			return ErrConflict
		}
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteProxy(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `UPDATE upstream_keys SET proxy_id=NULL, updated_at=? WHERE proxy_id=?`, nowMS(), id); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM proxies WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return tx.Commit()
}

func (s *Store) TouchProxyOK(ctx context.Context, id int64, ip, country string, latencyMS int64) error {
	now := nowMS()
	_, err := s.db.ExecContext(ctx, `UPDATE proxies SET fail_count=0, cooldown_until=0, last_ok_at=?, last_err='',
		last_ip=CASE WHEN ?='' THEN last_ip ELSE ? END,
		last_country=CASE WHEN ?='' THEN last_country ELSE ? END,
		last_latency_ms=CASE WHEN ?<=0 THEN last_latency_ms ELSE ? END,
		updated_at=? WHERE id=?`,
		now, ip, ip, country, country, latencyMS, latencyMS, now, id)
	return err
}

func (s *Store) TouchProxyErr(ctx context.Context, id int64, msg string, cooldownMS int64) error {
	now := nowMS()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	_, err := s.db.ExecContext(ctx, `UPDATE proxies SET fail_count=fail_count+1, cooldown_until=?, last_err_at=?, last_err=?, updated_at=? WHERE id=?`,
		cooldownMS, now, msg, now, id)
	return err
}

func percentile(vals []int64, p int) int64 {
	if len(vals) == 0 {
		return 0
	}
	idx := (len(vals) - 1) * p / 100
	return vals[idx]
}

type scanner interface {
	Scan(dest ...any) error
}

func scanUpstream(row scanner) (Upstream, error) {
	var u Upstream
	var lastOK, lastErr, proxyID sql.NullInt64
	var lastErrS sql.NullString
	err := row.Scan(&u.ID, &u.Name, &u.KeyEnc, &u.KeyPrefix, &u.KeyLast4, &u.Weight, &u.RPMLimit, &u.Status, &u.FailCount, &u.CooldownUntil, &lastOK, &lastErr, &lastErrS, &u.CreatedAt, &u.UpdatedAt, &proxyID)
	if err != nil {
		return u, err
	}
	if lastOK.Valid {
		v := lastOK.Int64
		u.LastOKAt = &v
	}
	if lastErr.Valid {
		v := lastErr.Int64
		u.LastErrAt = &v
	}
	if lastErrS.Valid {
		u.LastErr = lastErrS.String
	}
	if proxyID.Valid {
		v := proxyID.Int64
		u.ProxyID = &v
	}
	return u, nil
}

func scanProxy(row scanner, withBound bool) (Proxy, error) {
	var p Proxy
	var lastOK, lastErr sql.NullInt64
	var lastErrS sql.NullString
	args := []any{
		&p.ID, &p.Name, &p.Protocol, &p.Host, &p.Port, &p.Username, &p.Password, &p.Status,
		&p.FailCount, &p.CooldownUntil, &lastOK, &lastErr, &lastErrS, &p.LastIP, &p.LastCountry,
		&p.LastLatencyMS, &p.CreatedAt, &p.UpdatedAt,
	}
	if withBound {
		args = append(args, &p.BoundCount)
	}
	if err := row.Scan(args...); err != nil {
		return p, err
	}
	if lastOK.Valid {
		v := lastOK.Int64
		p.LastOKAt = &v
	}
	if lastErr.Valid {
		v := lastErr.Int64
		p.LastErrAt = &v
	}
	if lastErrS.Valid {
		p.LastErr = lastErrS.String
	}
	return p, nil
}

func scanUser(row scanner) (UserKey, error) {
	var k UserKey
	var exp, last sql.NullInt64
	err := row.Scan(&k.ID, &k.Name, &k.KeyHash, &k.KeyPrefix, &k.KeyLast4, &k.RPMLimit, &k.TokenQuota, &k.TokensUsed, &k.Status, &exp, &last, &k.Note, &k.CreatedAt, &k.UpdatedAt)
	if err != nil {
		return k, err
	}
	if exp.Valid {
		v := exp.Int64
		k.ExpiresAt = &v
	}
	if last.Valid {
		v := last.Int64
		k.LastUsedAt = &v
	}
	return k, nil
}

func nz(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

func nstr(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

func nullInt(v *int64) any {
	if v == nil {
		return nil
	}
	return *v
}

func PrefixLast4(plain string) (string, string) {
	last4 := plain
	if len(plain) >= 4 {
		last4 = plain[len(plain)-4:]
	}
	prefix := "jev_"
	switch {
	case strings.HasPrefix(plain, "jev_"):
		prefix = "jev_"
	case strings.HasPrefix(plain, "ts_"):
		prefix = "ts_"
	case strings.HasPrefix(plain, "apikey_"):
		prefix = "apikey_"
	case strings.HasPrefix(plain, "key_"):
		prefix = "key_"
	case strings.HasPrefix(plain, "sk-"):
		i := strings.Index(plain[3:], "-")
		if i >= 0 && i < 12 {
			prefix = plain[:3+i+1]
		} else {
			prefix = "sk-"
		}
	}
	return prefix, last4
}

func FmtErr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
