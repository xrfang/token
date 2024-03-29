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
	if ident != 123456 {
		t.Fatalf("token uid should be 123456, got %v", ident)
	}
	t.Logf("token is valid for uid#%d", ident)
}

func TestExpiredToken(t *testing.T) {
	uid := uint64(123456)
	exp := time.Now().Add(time.Second)
	tok := New(uid, exp)
	t.Logf("generated token for uid#%d: %s", uid, tok)
	t.Logf("token will expire after %s", exp.Format(time.RFC3339))
	_, err := Verify(tok)
	if err != nil {
		t.Fatalf("token expired prematurely")
	}
	time.Sleep(time.Second)
	_, err = Verify(tok)
	now := time.Now()
	if err == nil {
		t.Fatalf("token is still valid at %s", now.Format(time.RFC3339))
	}
	t.Logf("token is expired at %s (err=%v)", now.Format(time.RFC3339), err)
	ident, exp, err := Inspect(tok)
	t.Logf("ident: %v; expire=%v; err=%v", ident, exp, err)
}

func TestRevokeToken(t *testing.T) {
	uid := uint64(123456)
	tok1 := New(uid, time.Now().Add(time.Minute))
	tok2 := New(uid, time.Now().Add(time.Minute))
	if _, err := Verify(tok1); err != nil {
		t.Fatalf("TestRevokeToken: token1 verification failed")
	}
	if _, err := Verify(tok2); err != nil {
		t.Fatalf("TestRevokeToken: token2 verification failed")
	}
	t.Logf("generated two tokens: %q, %q", tok1, tok2)
	Revoke(tok2)
	if _, err := Verify(tok1); err != nil {
		t.Fatalf("TestRevokeToken: token1 mistakenly revoked")
	}
	if _, err := Verify(tok2); err == nil {
		t.Fatalf("TestRevokeToken: token2 revokation failed")
	}
	t.Log("token2 revoked successfully while token1 unaffected")
}

func TestRevokeAllTokens(t *testing.T) {
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
