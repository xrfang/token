package token

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

func assert(e interface{}) {
	if e != nil {
		panic(e)
	}
}

type Token struct {
	on  sync.Once
	key atomic.Value
	rev sync.Map
	cln chan bool
	chg atomic.Bool
}

func (t *Token) New(ident uint64, expire time.Time) string {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf, uint32(expire.Unix()))
	raw := append([]byte{}, buf[:4]...)
	binary.LittleEndian.PutUint64(buf, ident)
	raw = append(raw, bytes.TrimRight(buf, string([]byte{0}))...)
	k := t.key.Load()
	blk, _ := aes.NewCipher(k.([]byte))
	gcm, _ := cipher.NewGCM(blk)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	enc := gcm.Seal(nil, nonce, raw, nil)
	return hex.EncodeToString(append(nonce, enc...))
}

func (t *Token) Inspect(token string) (ident uint64, expire time.Time, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = errors.New("corrupted token")
		}
	}()
	data, err := hex.DecodeString(token)
	assert(err)
	k := t.key.Load()
	blk, _ := aes.NewCipher(k.([]byte))
	gcm, _ := cipher.NewGCM(blk)
	ns := gcm.NonceSize()
	nonce := data[:ns]
	data = data[ns:]
	dec, err := gcm.Open(nil, nonce, data, nil)
	assert(err)
	if _, ok := t.rev.Load(token); ok {
		err = errors.New("revoked token")
		return
	}
	timestamp := binary.LittleEndian.Uint32(dec)
	expire = time.Unix(int64(timestamp), 0)
	buf := make([]byte, 8)
	copy(buf, dec[4:])
	ident = binary.LittleEndian.Uint64(buf)
	return
}

func (t *Token) Verify(token string) (ident uint64, err error) {
	var exp time.Time
	ident, exp, err = t.Inspect(token)
	if err == nil && time.Now().After(exp) {
		err = errors.New("expired token")
	}
	return
}

func (t *Token) Revoke(token string) {
	t.rev.Store(token, true)
	t.chg.Store(true)
	t.cln <- true
}

func (t *Token) RevokeAll() {
	key := make([]byte, 16)
	rand.Read(key)
	t.key.Store(key)
	t.rev.Range(func(k, v any) bool {
		t.rev.Delete(k)
		return true
	})
	t.chg.Store(true)
}

func (t *Token) Changed() bool {
	return t.chg.Load()
}

func (t *Token) Reset() {
	t.chg.Store(false)
}

func (t *Token) Revoked() []string {
	var rt []string
	t.rev.Range(func(k, v any) bool {
		rt = append(rt, k.(string))
		return true
	})
	return rt
}

func (t *Token) Seed() []byte {
	return t.key.Load().([]byte)
}

func (t *Token) Init(seed []byte) (err error) {
	t.on.Do(func() {
		t.cln = make(chan bool)
		go func() {
			for {
				<-t.cln
				t.rev.Range(func(k, v any) bool {
					if _, err := Verify(k.(string)); err != nil {
						t.rev.Delete(k)
					}
					return true
				})
			}
		}()
	})
	switch len(seed) {
	case 0:
		seed = make([]byte, 16)
		rand.Read(seed)
		fallthrough
	case 16:
		t.key.Store(seed)
		t.chg.Store(true)
		return nil
	default:
		return errors.New("length of seed must be 16 bytes")
	}
}

var (
	defaultToken Token
)

func init() {
	defaultToken.Init(nil)
}
