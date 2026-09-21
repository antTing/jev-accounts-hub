package pool

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"jevproxy/internal/cryptox"
	"jevproxy/internal/store"
)

var ErrNoUpstream = errors.New("no available upstream key")

type selected struct {
	Up     store.Upstream
	APIKey string
}

type Pool struct {
	store  *store.Store
	box    *cryptox.AESGCM
	cursor uint64
}

func New(s *store.Store, box *cryptox.AESGCM) *Pool {
	return &Pool{store: s, box: box}
}

func (p *Pool) Pick(ctx context.Context, exclude map[int64]struct{}) (selected, error) {
	items, err := p.store.ListUpstreams(ctx)
	if err != nil {
		return selected{}, err
	}
	now := time.Now().UnixMilli()
	var candidates []store.Upstream
	for _, u := range items {
		if u.Status != "active" {
			continue
		}
		if u.CooldownUntil > now {
			continue
		}
		if exclude != nil {
			if _, skip := exclude[u.ID]; skip {
				continue
			}
		}
		candidates = append(candidates, u)
	}
	if len(candidates) == 0 {
		return selected{}, ErrNoUpstream
	}

	total := 0
	for _, u := range candidates {
		w := u.Weight
		if w <= 0 {
			w = 1
		}
		total += w
	}
	n := int(atomic.AddUint64(&p.cursor, 1) % uint64(total))
	acc := 0
	var pick store.Upstream
	for _, u := range candidates {
		w := u.Weight
		if w <= 0 {
			w = 1
		}
		acc += w
		if n < acc {
			pick = u
			break
		}
	}

	plain, err := p.box.Decrypt(pick.KeyEnc)
	if err != nil {
		return selected{}, err
	}
	return selected{Up: pick, APIKey: string(plain)}, nil
}

func (p *Pool) MarkOK(ctx context.Context, id int64) {
	_ = p.store.TouchUpstreamOK(ctx, id)
}

func (p *Pool) MarkErr(ctx context.Context, id int64, msg string, status int) {
	cool := time.Now().Add(15 * time.Second).UnixMilli()
	authFail := status == 401 || status == 403
	switch {
	case status == 429:
		cool = time.Now().Add(30 * time.Second).UnixMilli()
	case status == 529:
		cool = time.Now().Add(10 * time.Second).UnixMilli()
	case authFail:
		cool = time.Now().Add(10 * time.Minute).UnixMilli()
	case status >= 500:
		cool = time.Now().Add(20 * time.Second).UnixMilli()
	}
	_ = p.store.TouchUpstreamErr(ctx, id, msg, cool, authFail)
}

func (p *Pool) Decrypt(u store.Upstream) (string, error) {
	b, err := p.box.Decrypt(u.KeyEnc)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
