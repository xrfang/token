package token

import (
	"testing"
	"time"
)

func TestValidToken(t *testing.T) {
	uid := uint64(123456)
	tok := New(uid, time.Now().Add(time.Minute))
	t.Logf("generated token for uid#%d: %s", uid, tok)
	ident, err := Verify(tok)
	if err != nil {
		t.Fatalf(err.Error())
	}
	t.Logf("token is valid for uid#%d", ident)
}

func TestExpiredToken(t *testing.T) {
	uid := uint64(123456)
	exp := time.Now()
	tok := New(uid, exp)
	t.Logf("generated token for uid#%d: %s", uid, tok)
	t.Logf("token will expire after %s", exp)
	_, err := Verify(tok)
	now := time.Now()
	if err == nil {
		t.Fatalf("token is still valid at %s", now)
	}
	t.Logf("token is expired at %s (err=%v)", now, err)
}
