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

func TestRevokeTokens(t *testing.T) {
	uid := uint64(123456)
	tok1 := New(uid, time.Now().Add(time.Minute))
	tok2 := New(uid, time.Now().Add(time.Minute))
	_, err1 := Verify(tok1)
	_, err2 := Verify(tok2)
	if err1 == nil && err2 == nil {
		t.Logf("generated two tokens: %q, %q", tok1, tok2)
	} else {
		t.Fatalf("TestRevokeTokens: token verification failed")
	}
	RevokeAll()
	_, err1 = Verify(tok1)
	_, err2 = Verify(tok2)
	if err1 == nil || err2 == nil {
		if err1 == nil {
			t.Logf("%q still valid after revocation", tok1)
		}
		if err2 == nil {
			t.Logf("%q still valid after revocation", tok2)
		}
		t.Fatalf("TestRevokeTokens: token revocation failed")
	}
	t.Log("two tokens revoked successfully")
}
