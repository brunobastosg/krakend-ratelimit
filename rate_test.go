package krakendrate

import (
	"github.com/luraproject/lura/v2/logging"
	"testing"
)

func TestNewMemoryStore(t *testing.T) {
	store := NewMemoryStore(1, 1, logging.NoOp)
	limiter1 := store("1", 0, 0)
	if !limiter1.Allow() {
		t.Error("The limiter should allow the first call")
	}
	if limiter1.Allow() {
		t.Error("The limiter should block the second call")
	}
	if store("1", 0, 0).Allow() {
		t.Error("The limiter should block the third call")
	}
	if !store("2", 0, 0).Allow() {
		t.Error("The limiter should allow the fourth call because it requests a new limiter")
	}

	if !store("3", 3, 3).Allow() {
		t.Error("The limiter should allow 1st call for token 3 because it requests a new limiter")
	}

	if !store("3", 3, 3).Allow() {
		t.Error("The limiter should allow 2nd call for token 3 because it has a dynamic capacity 3 and max rate 3")
	}

	if !store("3", 3, 3).Allow() {
		t.Error("The limiter should allow 3rd call for token 3 because it has a dynamic capacity 3 and max rate 3")
	}

	if store("3", 3, 3).Allow() {
		t.Error("The limiter should not allow 4th call for token 3 because it has a dynamic capacity 3 and max rate 3")
	}
}
