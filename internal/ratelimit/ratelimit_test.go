package ratelimit

import (
	"testing"
	"time"
)

func TestKeyed(t *testing.T) {
	k := New(time.Hour, 3)
	for i := 0; i < 3; i++ {
		if !k.Allow("a") {
			t.Fatalf("burst token %d denied", i)
		}
	}
	if k.Allow("a") {
		t.Fatal("over-limit request allowed")
	}
	if !k.Allow("b") {
		t.Fatal("keys are not independent")
	}
	if k.AllowN("c", 4) {
		t.Fatal("AllowN above burst allowed")
	}
}

func TestKeyExhaustionFailsClosed(t *testing.T) {
	k := New(time.Hour, 1)
	k.maxKeys = 2
	k.Allow("a")
	k.Allow("b")
	if k.Allow("c") {
		t.Fatal("new key admitted while table is full of active keys")
	}
}
