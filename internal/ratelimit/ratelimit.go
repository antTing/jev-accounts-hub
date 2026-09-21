package ratelimit

import (
	"sync"
	"time"
)

// Limiter 进程内滑动窗口 RPM。单实例够用；多实例再换 Redis。
type Limiter struct {
	mu      sync.Mutex
	windows map[string]*window
}

type window struct {
	times []int64
}

func New() *Limiter {
	l := &Limiter{windows: make(map[string]*window)}
	go l.gc()
	return l
}

func (l *Limiter) Allow(key string, rpm int) (ok bool, retryAfter time.Duration) {
	if rpm <= 0 {
		return true, 0
	}
	now := time.Now().UnixMilli()
	cutoff := now - 60_000

	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.windows[key]
	if w == nil {
		w = &window{}
		l.windows[key] = w
	}
	i := 0
	for i < len(w.times) && w.times[i] <= cutoff {
		i++
	}
	if i > 0 {
		w.times = append([]int64{}, w.times[i:]...)
	}
	if len(w.times) >= rpm {
		oldest := w.times[0]
		wait := time.Duration(oldest+60_000-now) * time.Millisecond
		if wait < time.Second {
			wait = time.Second
		}
		return false, wait
	}
	w.times = append(w.times, now)
	return true, 0
}

func (l *Limiter) gc() {
	t := time.NewTicker(2 * time.Minute)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().UnixMilli() - 120_000
		l.mu.Lock()
		for k, w := range l.windows {
			i := 0
			for i < len(w.times) && w.times[i] <= cutoff {
				i++
			}
			if i == len(w.times) {
				delete(l.windows, k)
				continue
			}
			w.times = append([]int64{}, w.times[i:]...)
		}
		l.mu.Unlock()
	}
}
