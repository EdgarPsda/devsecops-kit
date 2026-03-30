package ai

import (
	"crypto/sha256"
	"fmt"
	"sync"
)

// Cache stores AI suggestions keyed by a hash of rule+message.
// Thread-safe for concurrent enrichment.
type Cache struct {
	mu    sync.RWMutex
	store map[string]string
}

func NewCache() *Cache {
	return &Cache{store: make(map[string]string)}
}

func (c *Cache) Get(key string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.store[key]
	return v, ok
}

func (c *Cache) Set(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = value
}

// cacheKey returns a stable key for a rule ID + message pair
func cacheKey(ruleID, message string) string {
	h := sha256.Sum256([]byte(ruleID + "\x00" + message))
	return fmt.Sprintf("%x", h[:8])
}
