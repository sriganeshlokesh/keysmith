package service

import (
	"strings"
	"testing"
)

func TestPasswordHashRoundtrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash = %q, want argon2id encoded string", hash)
	}

	ok, err := VerifyPassword("correct horse battery staple", hash)
	if err != nil || !ok {
		t.Errorf("VerifyPassword(correct) = %v, %v; want true, nil", ok, err)
	}
	ok, err = VerifyPassword("wrong password", hash)
	if err != nil || ok {
		t.Errorf("VerifyPassword(wrong) = %v, %v; want false, nil", ok, err)
	}
}

func TestPasswordHashIsSalted(t *testing.T) {
	a, err := HashPassword("same password")
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}
	b, err := HashPassword("same password")
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}
	if a == b {
		t.Error("two hashes of the same password are identical — salt missing")
	}
}
