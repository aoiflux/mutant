package builtin

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	crankcql "github.com/shreybatra/crankdb/cql"
	crankserver "github.com/shreybatra/crankdb/server"

	"mutant/object"
)

type cacheEntry struct {
	expiresAt time.Time
}

type cacheStore struct {
	entries map[string]cacheEntry
	db      *crankserver.Database
	stats   cacheStoreStats
}

type cacheStoreStats struct {
	hits    int64
	misses  int64
	puts    int64
	deletes int64
	expires int64
	clears  int64
}

var runtimeCacheStores = struct {
	sync.RWMutex
	stores map[string]*cacheStore
}{
	stores: map[string]*cacheStore{},
}

var crankRuntime = struct {
	sync.Mutex
	server *crankserver.CrankServer
}{
	server: &crankserver.CrankServer{},
}

func CacheOpen(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	nameObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `cache_open` must be STRING, got %s", args[0].Type()))
	}
	if nameObj.Value == "" {
		return resultAndError(nil, newError("argument 1 to `cache_open` must not be empty"))
	}

	runtimeCacheStores.Lock()
	_, exists := runtimeCacheStores.stores[nameObj.Value]
	if !exists {
		runtimeCacheStores.stores[nameObj.Value] = &cacheStore{
			entries: map[string]cacheEntry{},
			db:      crankserver.NewDatabase(),
		}
	}
	runtimeCacheStores.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"name":    stringObj(nameObj.Value),
		"opened":  boolObj(true),
		"created": boolObj(!exists),
	}), nil)
}

func CachePut(args ...object.Object) object.Object {
	if len(args) != 3 && len(args) != 4 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=3 or 4", len(args)))
	}

	cacheName, key, errObj := cacheNameAndKey("cache_put", args[0], args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	store, errObj := cacheStoreByName(cacheName)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	expiresAt := time.Time{}
	if len(args) == 4 {
		ttlObj, ok := args[3].(*object.Integer)
		if !ok {
			return resultAndError(nil, newError("argument 4 to `cache_put` must be INTEGER, got %s", args[3].Type()))
		}
		if ttlObj.Value < 0 {
			return resultAndError(nil, newError("argument 4 to `cache_put` must be >= 0"))
		}
		if ttlObj.Value > 0 {
			expiresAt = time.Now().UTC().Add(time.Duration(ttlObj.Value) * time.Second)
		}
	}

	if errObj := cacheSetJSON(store, key, args[2]); errObj != nil {
		return resultAndError(nil, errObj)
	}

	runtimeCacheStores.Lock()
	store.entries[key] = cacheEntry{expiresAt: expiresAt}
	store.stats.puts++
	runtimeCacheStores.Unlock()

	return resultAndError(boolObj(true), nil)
}

func CacheGet(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	cacheName, key, errObj := cacheNameAndKey("cache_get", args[0], args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	store, errObj := cacheStoreByName(cacheName)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	now := time.Now().UTC()
	runtimeCacheStores.Lock()
	entry, ok := store.entries[key]
	if ok && !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
		delete(store.entries, key)
		store.stats.expires++
		ok = false
	}
	if ok {
		store.stats.hits++
	} else {
		store.stats.misses++
	}
	runtimeCacheStores.Unlock()

	if !ok {
		return resultAndError(makeHashObject(map[string]object.Object{
			"found": boolObj(false),
			"value": &object.Null{},
		}), nil)
	}

	value, errObj := cacheGetJSON(store, key)
	if errObj != nil {
		if strings.Contains(strings.ToLower(errObj.Message), "not found") {
			runtimeCacheStores.Lock()
			delete(store.entries, key)
			store.stats.misses++
			runtimeCacheStores.Unlock()
			return resultAndError(makeHashObject(map[string]object.Object{
				"found": boolObj(false),
				"value": &object.Null{},
			}), nil)
		}
		return resultAndError(nil, errObj)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"found": boolObj(true),
		"value": value,
	}), nil)
}

func CacheDelete(args ...object.Object) object.Object {
	if len(args) != 2 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2", len(args)))
	}

	cacheName, key, errObj := cacheNameAndKey("cache_delete", args[0], args[1])
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	store, errObj := cacheStoreByName(cacheName)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	runtimeCacheStores.Lock()
	_, existed := store.entries[key]
	if existed {
		delete(store.entries, key)
		store.stats.deletes++
	}
	runtimeCacheStores.Unlock()

	if existed {
		_ = cacheSetJSON(store, key, &object.Null{})
	}

	return resultAndError(boolObj(existed), nil)
}

func CacheKeys(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	cacheNameObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `cache_keys` must be STRING, got %s", args[0].Type()))
	}

	store, errObj := cacheStoreByName(cacheNameObj.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	now := time.Now().UTC()
	runtimeCacheStores.Lock()
	cacheCleanupExpiredLocked(store, now)
	keys := make([]string, 0, len(store.entries))
	for key := range store.entries {
		keys = append(keys, key)
	}
	runtimeCacheStores.Unlock()

	sort.Strings(keys)
	elements := make([]object.Object, len(keys))
	for i, key := range keys {
		elements[i] = stringObj(key)
	}
	return resultAndError(&object.Array{Elements: elements}, nil)
}

func CacheStats(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	cacheNameObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `cache_stats` must be STRING, got %s", args[0].Type()))
	}

	store, errObj := cacheStoreByName(cacheNameObj.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	now := time.Now().UTC()
	runtimeCacheStores.Lock()
	cacheCleanupExpiredLocked(store, now)
	items := int64(len(store.entries))
	stats := store.stats
	runtimeCacheStores.Unlock()

	return resultAndError(makeHashObject(map[string]object.Object{
		"name":    stringObj(cacheNameObj.Value),
		"items":   intObj(items),
		"hits":    intObj(stats.hits),
		"misses":  intObj(stats.misses),
		"puts":    intObj(stats.puts),
		"deletes": intObj(stats.deletes),
		"expires": intObj(stats.expires),
		"clears":  intObj(stats.clears),
	}), nil)
}

func CacheClear(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}

	cacheNameObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `cache_clear` must be STRING, got %s", args[0].Type()))
	}

	store, errObj := cacheStoreByName(cacheNameObj.Value)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	runtimeCacheStores.Lock()
	removed := int64(len(store.entries))
	store.entries = map[string]cacheEntry{}
	store.db = crankserver.NewDatabase()
	store.stats.clears++
	runtimeCacheStores.Unlock()

	return resultAndError(intObj(removed), nil)
}

func cacheNameAndKey(opName string, cacheNameObj object.Object, keyObj object.Object) (string, string, *object.Error) {
	cacheName, ok := cacheNameObj.(*object.String)
	if !ok {
		return "", "", newError("argument 1 to `%s` must be STRING, got %s", opName, cacheNameObj.Type())
	}
	key, ok := keyObj.(*object.String)
	if !ok {
		return "", "", newError("argument 2 to `%s` must be STRING, got %s", opName, keyObj.Type())
	}
	return cacheName.Value, key.Value, nil
}

func cacheStoreByName(name string) (*cacheStore, *object.Error) {
	runtimeCacheStores.RLock()
	store, ok := runtimeCacheStores.stores[name]
	runtimeCacheStores.RUnlock()
	if !ok {
		return nil, newError("cache `%s` not found; call `cache_open` first", name)
	}
	return store, nil
}

func cacheCleanupExpiredLocked(store *cacheStore, now time.Time) {
	for key, entry := range store.entries {
		if !entry.expiresAt.IsZero() && now.After(entry.expiresAt) {
			delete(store.entries, key)
			store.stats.expires++
		}
	}
}

func cacheSetJSON(store *cacheStore, key string, value object.Object) *object.Error {
	goVal, err := objectToJSONValue(value)
	if err != nil {
		return newError("cache backend encode: %s", err.Error())
	}
	jsonBytes, err := json.Marshal(goVal)
	if err != nil {
		return newError("cache backend encode: %s", err.Error())
	}

	crankRuntime.Lock()
	orig := crankserver.Db
	crankserver.Db = store.db
	_, callErr := crankRuntime.server.Set(context.Background(), &crankcql.DataPacket{
		Key:      key,
		DataType: crankcql.DataType_JSON,
		JsonVal:  jsonBytes,
	})
	crankserver.Db = orig
	crankRuntime.Unlock()

	if callErr != nil {
		return newError("cache backend set: %s", callErr.Error())
	}
	return nil
}

func cacheGetJSON(store *cacheStore, key string) (object.Object, *object.Error) {
	crankRuntime.Lock()
	orig := crankserver.Db
	crankserver.Db = store.db
	packet, callErr := crankRuntime.server.Get(context.Background(), &crankcql.GetCommandRequest{Key: key})
	crankserver.Db = orig
	crankRuntime.Unlock()

	if callErr != nil {
		return nil, newError("cache backend get: %s", callErr.Error())
	}

	if packet.GetDataType() != crankcql.DataType_JSON {
		return nil, newError("cache backend get: unsupported type %s", packet.GetDataType().String())
	}

	var raw any
	if err := json.Unmarshal(packet.GetJsonVal(), &raw); err != nil {
		return nil, newError("cache backend decode: %s", err.Error())
	}

	obj, err := jsonValueToObject(raw)
	if err != nil {
		return nil, newError("cache backend decode: %s", err.Error())
	}
	return obj, nil
}
