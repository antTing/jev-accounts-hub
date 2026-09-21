package outproxy

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"jevproxy/internal/store"
)

var ErrBoundUnavailable = errors.New("bound proxy unavailable")

type Choice struct {
	Proxy  *store.Proxy // nil = 直连
	Direct bool
}

func (c Choice) ID() int64 {
	if c.Proxy == nil {
		return 0
	}
	return c.Proxy.ID
}

type Picker struct {
	store  *store.Store
	cursor uint64
}

func NewPicker(st *store.Store) *Picker {
	return &Picker{store: st}
}

// Pick 按账号绑定选择出口。
//
//	ProxyID == nil → 共享池轮询，池空则直连
//	ProxyID == 0   → 强制直连
//	ProxyID == N   → 绑定 N；不可用则报错，绝不回退直连
func (p *Picker) Pick(ctx context.Context, up store.Upstream, exclude map[int64]struct{}) (Choice, error) {
	if up.ProxyID != nil {
		id := *up.ProxyID
		if id == 0 {
			return Choice{Direct: true}, nil
		}
		pr, err := p.store.GetProxy(ctx, id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return Choice{}, fmt.Errorf("%w: id %d not found", ErrBoundUnavailable, id)
			}
			return Choice{}, err
		}
		if pr.Status != "active" {
			return Choice{}, fmt.Errorf("%w: %s disabled", ErrBoundUnavailable, Redacted(pr))
		}
		if pr.CooldownUntil > time.Now().UnixMilli() {
			return Choice{}, fmt.Errorf("%w: %s cooling down", ErrBoundUnavailable, Redacted(pr))
		}
		cp := pr
		return Choice{Proxy: &cp}, nil
	}

	items, err := p.store.ListActiveProxies(ctx)
	if err != nil {
		return Choice{}, err
	}
	var cand []store.Proxy
	for _, pr := range items {
		if exclude != nil {
			if _, skip := exclude[pr.ID]; skip {
				continue
			}
		}
		cand = append(cand, pr)
	}
	if len(cand) == 0 {
		if len(items) == 0 {
			return Choice{Direct: true}, nil
		}
		return Choice{}, fmt.Errorf("no available proxy in pool")
	}
	n := int(atomic.AddUint64(&p.cursor, 1) % uint64(len(cand)))
	cp := cand[n]
	return Choice{Proxy: &cp}, nil
}

func CooldownMS() int64 {
	return time.Now().Add(30 * time.Second).UnixMilli()
}
