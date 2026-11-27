// Package ratelimit provides keyed token-bucket limiters with bounded memory.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Keyed holds one token bucket per key (IP address, user id, ...).
type Keyed struct {
	mu      sync.Mutex
	r       rate.Limit
	burst   int
	m       map[string]*entry
	maxKeys int
}

type entry struct {
	l    *rate.Limiter
	last time.Time
}

// New returns a limiter allowing `burst` events immediately and then one
// event every `every`.
func New(every time.Duration, burst int) *Keyed {
	return &Keyed{r: rate.Every(every), burst: burst, m: map[string]*entry{}, maxKeys: 100000}
}

// Allow consumes one token for key.
func (k *Keyed) Allow(key string) bool { return k.AllowN(key, 1) }

// AllowN consumes n tokens for key.
func (k *Keyed) AllowN(key string, n int) bool {
	now := time.Now()
	k.mu.Lock()
	defer k.mu.Unlock()
	e, ok := k.m[key]
	if !ok {
		if len(k.m) >= k.maxKeys {
			k.gcLocked(now, 0)
			if len(k.m) >= k.maxKeys {
				return false // fail closed under key-exhaustion attacks
			}
		}
		e = &entry{l: rate.NewLimiter(k.r, k.burst)}
		k.m[key] = e
	}
	e.last = now
	return e.l.AllowN(now, n)
}

// GC removes keys idle for longer than idle.
func (k *Keyed) GC(idle time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.gcLocked(time.Now(), idle)
}

func (k *Keyed) gcLocked(now time.Time, idle time.Duration) {
	for key, e := range k.m {
		// A bucket that has fully refilled carries no state worth keeping.
		if now.Sub(e.last) > idle && e.l.TokensAt(now) >= float64(k.burst) {
			delete(k.m, key)
		}
	}
}

// RunGC periodically garbage-collects idle keys until stop is closed.
func (k *Keyed) RunGC(stop <-chan struct{}, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			k.GC(every)
		}
	}
}
