package builtin

import (
	"testing"
	"time"

	"mutant/object"
)

func TestCacheOpenPutGet(t *testing.T) {
	_, errObj := unwrapPair(t, CacheOpen(stringObj("t_cache_1")))
	if errObj != nil {
		t.Fatalf("unexpected cache_open error: %s", errObj.Inspect())
	}

	_, errObj = unwrapPair(t, CachePut(stringObj("t_cache_1"), stringObj("k1"), stringObj("v1")))
	if errObj != nil {
		t.Fatalf("unexpected cache_put error: %s", errObj.Inspect())
	}

	payload, errObj := unwrapPair(t, CacheGet(stringObj("t_cache_1"), stringObj("k1")))
	if errObj != nil {
		t.Fatalf("unexpected cache_get error: %s", errObj.Inspect())
	}

	hashPayload, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("cache_get payload is not HASH. got=%T", payload)
	}

	foundObj := cacheTestMustHashValue(t, hashPayload, "found")
	found, ok := foundObj.(*object.Boolean)
	if !ok || !found.Value {
		t.Fatalf("expected found=true")
	}

	valueObj := cacheTestMustHashValue(t, hashPayload, "value")
	value, ok := valueObj.(*object.String)
	if !ok || value.Value != "v1" {
		t.Fatalf("unexpected cached value")
	}
}

func TestCacheTTLExpiry(t *testing.T) {
	_, errObj := unwrapPair(t, CacheOpen(stringObj("t_cache_ttl")))
	if errObj != nil {
		t.Fatalf("unexpected cache_open error: %s", errObj.Inspect())
	}

	_, errObj = unwrapPair(t, CachePut(stringObj("t_cache_ttl"), stringObj("k"), stringObj("v"), intObj(1)))
	if errObj != nil {
		t.Fatalf("unexpected cache_put error: %s", errObj.Inspect())
	}

	time.Sleep(1200 * time.Millisecond)

	payload, errObj := unwrapPair(t, CacheGet(stringObj("t_cache_ttl"), stringObj("k")))
	if errObj != nil {
		t.Fatalf("unexpected cache_get error: %s", errObj.Inspect())
	}

	hashPayload, ok := payload.(*object.Hash)
	if !ok {
		t.Fatalf("cache_get payload is not HASH. got=%T", payload)
	}

	foundObj := cacheTestMustHashValue(t, hashPayload, "found")
	found, ok := foundObj.(*object.Boolean)
	if !ok {
		t.Fatalf("found is not BOOLEAN. got=%T", foundObj)
	}
	if found.Value {
		t.Fatalf("expected cache entry to be expired")
	}
}

func TestCacheDeleteKeysStatsAndClear(t *testing.T) {
	_, errObj := unwrapPair(t, CacheOpen(stringObj("t_cache_2")))
	if errObj != nil {
		t.Fatalf("unexpected cache_open error: %s", errObj.Inspect())
	}

	_, errObj = unwrapPair(t, CachePut(stringObj("t_cache_2"), stringObj("a"), intObj(1)))
	if errObj != nil {
		t.Fatalf("unexpected cache_put error: %s", errObj.Inspect())
	}
	_, errObj = unwrapPair(t, CachePut(stringObj("t_cache_2"), stringObj("b"), intObj(2)))
	if errObj != nil {
		t.Fatalf("unexpected cache_put error: %s", errObj.Inspect())
	}

	keysPayload, errObj := unwrapPair(t, CacheKeys(stringObj("t_cache_2")))
	if errObj != nil {
		t.Fatalf("unexpected cache_keys error: %s", errObj.Inspect())
	}
	keysArr, ok := keysPayload.(*object.Array)
	if !ok {
		t.Fatalf("cache_keys payload is not ARRAY. got=%T", keysPayload)
	}
	if len(keysArr.Elements) != 2 {
		t.Fatalf("unexpected key count. got=%d, want=2", len(keysArr.Elements))
	}

	deletePayload, errObj := unwrapPair(t, CacheDelete(stringObj("t_cache_2"), stringObj("a")))
	if errObj != nil {
		t.Fatalf("unexpected cache_delete error: %s", errObj.Inspect())
	}
	deleted, ok := deletePayload.(*object.Boolean)
	if !ok || !deleted.Value {
		t.Fatalf("expected delete=true")
	}

	statsPayload, errObj := unwrapPair(t, CacheStats(stringObj("t_cache_2")))
	if errObj != nil {
		t.Fatalf("unexpected cache_stats error: %s", errObj.Inspect())
	}
	statsHash, ok := statsPayload.(*object.Hash)
	if !ok {
		t.Fatalf("cache_stats payload is not HASH. got=%T", statsPayload)
	}
	itemsObj := cacheTestMustHashValue(t, statsHash, "items")
	items, ok := itemsObj.(*object.Integer)
	if !ok || items.Value != 1 {
		t.Fatalf("unexpected items count. got=%v", itemsObj.Inspect())
	}

	clearPayload, errObj := unwrapPair(t, CacheClear(stringObj("t_cache_2")))
	if errObj != nil {
		t.Fatalf("unexpected cache_clear error: %s", errObj.Inspect())
	}
	removed, ok := clearPayload.(*object.Integer)
	if !ok || removed.Value != 1 {
		t.Fatalf("unexpected removed count. got=%v", clearPayload.Inspect())
	}
}

func TestCacheBuiltinsErrors(t *testing.T) {
	tests := []struct {
		name string
		call func() object.Object
	}{
		{
			name: "cache_put wrong key type",
			call: func() object.Object {
				return CachePut(stringObj("missing"), intObj(1), stringObj("v"))
			},
		},
		{
			name: "cache_put negative ttl",
			call: func() object.Object {
				_, _ = unwrapPair(t, CacheOpen(stringObj("t_cache_err")))
				return CachePut(stringObj("t_cache_err"), stringObj("k"), stringObj("v"), intObj(-1))
			},
		},
		{
			name: "cache_get missing cache",
			call: func() object.Object {
				return CacheGet(stringObj("does-not-exist"), stringObj("k"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.call()
			_, errObj := unwrapPair(t, result)
			if errObj == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func cacheTestMustHashValue(t *testing.T, hash *object.Hash, key string) object.Object {
	t.Helper()
	keyObj := &object.String{Value: key}
	pair, ok := hash.Pairs[keyObj.HashKey()]
	if !ok {
		t.Fatalf("missing hash key %q", key)
	}
	return pair.Value
}
