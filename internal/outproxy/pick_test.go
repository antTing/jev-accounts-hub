package outproxy

import (
	"context"
	"testing"
	"time"

	"jevproxy/internal/store"
)

func TestPickBoundPoolDirect(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	pk := NewPicker(st)

	zero := int64(0)
	ch, err := pk.Pick(ctx, store.Upstream{ProxyID: &zero}, nil)
	if err != nil || !ch.Direct || ch.Proxy != nil {
		t.Fatalf("force direct %+v %v", ch, err)
	}

	ch, err = pk.Pick(ctx, store.Upstream{ProxyID: nil}, nil)
	if err != nil || !ch.Direct {
		t.Fatalf("empty pool should direct %+v %v", ch, err)
	}

	id, err := st.InsertProxy(ctx, store.Proxy{Name: "p1", Protocol: "http", Host: "127.0.0.1", Port: 8080, Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	ch, err = pk.Pick(ctx, store.Upstream{ProxyID: nil}, nil)
	if err != nil || ch.Direct || ch.Proxy == nil || ch.Proxy.ID != id {
		t.Fatalf("pool pick %+v %v", ch, err)
	}

	bound := id
	ch, err = pk.Pick(ctx, store.Upstream{ProxyID: &bound}, nil)
	if err != nil || ch.Proxy == nil || ch.Proxy.ID != id {
		t.Fatalf("bound %+v %v", ch, err)
	}

	missing := int64(999)
	if _, err := pk.Pick(ctx, store.Upstream{ProxyID: &missing}, nil); err == nil {
		t.Fatal("missing bound should fail, not fall back")
	}

	if err := st.UpdateProxy(ctx, id, "p1", "http", "127.0.0.1", 8080, "", "", "disabled"); err != nil {
		t.Fatal(err)
	}
	if _, err := pk.Pick(ctx, store.Upstream{ProxyID: &bound}, nil); err == nil {
		t.Fatal("disabled bound should fail")
	}

	id2, err := st.InsertProxy(ctx, store.Proxy{Name: "p2", Protocol: "http", Host: "10.0.0.2", Port: 8080, Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	_ = st.TouchProxyErr(ctx, id2, "boom", time.Now().Add(time.Minute).UnixMilli())
	ch, err = pk.Pick(ctx, store.Upstream{ProxyID: nil}, nil)
	if err != nil || !ch.Direct {
		t.Fatalf("empty live pool should direct %+v %v", ch, err)
	}

	id3, err := st.InsertProxy(ctx, store.Proxy{Name: "p3", Protocol: "http", Host: "10.0.0.3", Port: 8080, Status: "active"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pk.Pick(ctx, store.Upstream{ProxyID: nil}, map[int64]struct{}{id3: {}}); err == nil {
		t.Fatal("excluding last live proxy must not fall back to direct")
	}
}
