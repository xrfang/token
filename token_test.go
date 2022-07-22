package token

import (
	"net"
	"testing"
	"time"
)

func TestValidToken(t *testing.T) {
	uid := uint64(123456)
	tok := New(uid, time.Now().Add(time.Minute), nil)
	t.Logf("generated token for uid#%d: %s", uid, tok)
	ident, err := Verify(tok, nil)
	if err != nil {
		t.Fatalf(err.Error())
	}
	t.Logf("token is valid for uid#%d", ident)
}

func TestExpiredToken(t *testing.T) {
	uid := uint64(123456)
	exp := time.Now()
	tok := New(uid, exp, nil)
	t.Logf("generated token for uid#%d: %s", uid, tok)
	t.Logf("token will expire after %s", exp)
	_, err := Verify(tok, nil)
	now := time.Now()
	if err == nil {
		t.Fatalf("token is still valid at %s", now)
	}
	t.Logf("token is expired at %s (err=%v)", now, err)
}

func TestIllegalToken(t *testing.T) {
	uid := uint64(123456)
	owner := net.IPv4(127, 0, 0, 1)
	tok := New(uid, time.Now().Add(time.Minute), owner)
	t.Logf("generated token for uid#%d@%s: %s", uid, owner, tok)
	holder := net.IPv4(192, 168, 1, 1)
	_, err := Verify(tok, holder)
	if err == nil {
		t.Fatalf("token with owner %q is valid for %q", owner, holder)
	}
	t.Logf("token owned by %q not usable by %q: %v", owner, holder, err)
}
