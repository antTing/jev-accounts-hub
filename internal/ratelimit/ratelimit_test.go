package ratelimit

import "testing"

func TestAllow(t *testing.T) {
	l := New()
	if ok, _ := l.Allow("a", 2); !ok {
		t.Fatal("first")
	}
	if ok, _ := l.Allow("a", 2); !ok {
		t.Fatal("second")
	}
	if ok, wait := l.Allow("a", 2); ok || wait <= 0 {
		t.Fatalf("third should block, wait=%v", wait)
	}
}
