package service

import "github.com/alexedwards/argon2id"

// argonParams follow the security checklist (master plan §11): memory ≥64MB,
// 1–3 iterations, parallelism 2 — targeting roughly 100ms per hash.
var argonParams = &argon2id.Params{
	Memory:      64 * 1024, // KiB
	Iterations:  2,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

// HashPassword returns the argon2id encoded hash of password.
func HashPassword(password string) (string, error) {
	return argon2id.CreateHash(password, argonParams)
}

// VerifyPassword reports whether password matches the encoded hash in
// constant time.
func VerifyPassword(password, hash string) (bool, error) {
	return argon2id.ComparePasswordAndHash(password, hash)
}
