package store

import (
	"context"
	"testing"
	"time"
)

func TestUpstreamHashDedupAndLogs(t *testing.T) {
	st, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	id, err := st.InsertUpstream(ctx, Upstream{
		Name: "a", KeyEnc: []byte("enc"), KeyPrefix: "jev_", KeyLast4: "1111", KeyHash: "hash-a", Weight: 1, RPMLimit: 10, Status: "active",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.InsertUpstream(ctx, Upstream{
		Name: "b", KeyEnc: []byte("enc2"), KeyPrefix: "jev_", KeyLast4: "2222", KeyHash: "hash-a", Weight: 1, RPMLimit: 10,
	}); err != ErrConflict {
		t.Fatalf("want conflict got %v", err)
	}
	ok, err := st.UpstreamHashExists(ctx, "hash-a")
	if err != nil || !ok {
		t.Fatalf("exists %v %v", ok, err)
	}

	uid, err := st.InsertUserKey(ctx, UserKey{Name: "u", KeyHash: "uh", KeyPrefix: "sk-jev-", KeyLast4: "zzzz", RPMLimit: 60, Note: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateUserKey(ctx, uid, "u2", 12, 99, "active", nil, "n2"); err != nil {
		t.Fatal(err)
	}
	k, err := st.GetUserKey(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if k.Name != "u2" || k.Note != "n2" || k.TokenQuota != 99 || k.RPMLimit != 12 {
		t.Fatalf("%+v", k)
	}

	up := id
	_ = st.InsertLog(ctx, UsageLog{UserKeyID: uid, UpstreamID: &up, Model: "jev-latest", InputTokens: 3, StatusCode: 200, OK: true, RequestID: "r1"})
	_ = st.InsertLog(ctx, UsageLog{UserKeyID: uid, Model: "jev-latest", StatusCode: 502, OK: false, Error: "boom", RequestID: "r2"})

	fail := false
	items, total, err := st.ListLogs(ctx, LogFilter{OK: &fail, Q: "boom", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(items) != 1 || items[0].Error != "boom" {
		t.Fatalf("filter %+v total %d", items, total)
	}

	stt, err := st.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stt.Upstreams != 1 || stt.UserKeys != 1 || stt.ReqTotal < 2 {
		t.Fatalf("stats %+v", stt)
	}
	_ = time.Now()
}
