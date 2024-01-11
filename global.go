package token

import (
	"time"
)

func New(ident uint64, expire time.Time) string {
	return defaultToken.New(ident, expire)
}

func Inspect(token string) (ident uint64, expire time.Time, err error) {
	return defaultToken.Inspect(token)
}

func Verify(token string) (ident uint64, err error) {
	return defaultToken.Verify(token)
}

func Revoke(token string) {
	defaultToken.Revoke(token)
}

func RevokeAll() {
	defaultToken.RevokeAll()
}

func Seed() []byte {
	return defaultToken.Seed()
}

func Init(seed []byte) (err error) {
	return defaultToken.Init(seed)
}

func Revoked() []string {
	return defaultToken.Revoked()
}

func Changed() bool {
	return defaultToken.Changed()
}

func Reset() {
	defaultToken.Reset()
}
