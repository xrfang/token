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

func New(ident uint64, expire time.Time) string {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf, uint32(expire.Unix()))
	raw := append([]byte{}, buf[:4]...)
	binary.LittleEndian.PutUint64(buf, ident)
	raw = append(raw, bytes.TrimRight(buf, string([]byte{0}))...)
	k := tokenKey.Load()
	blk, _ := aes.NewCipher(k.([]byte))
	gcm, _ := cipher.NewGCM(blk)
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	enc := gcm.Seal(nil, nonce, raw, nil)
	return hex.EncodeToString(append(nonce, enc...))
}

func Verify(token string) (ident uint64, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = errors.New("corrupted token")
		}
	}()
	data, err := hex.DecodeString(token)
	assert(err)
	k := tokenKey.Load()
	blk, _ := aes.NewCipher(k.([]byte))
	gcm, _ := cipher.NewGCM(blk)
	ns := gcm.NonceSize()
	nonce := data[:ns]
	data = data[ns:]
	dec, err := gcm.Open(nil, nonce, data, nil)
	assert(err)
	timestamp := binary.LittleEndian.Uint32(dec)
	exp := time.Unix(int64(timestamp), 0)
	if time.Now().After(exp) {
		return 0, errors.New("expired token")
	}
	if _, ok := revoked.Load(token); ok {
		return 0, errors.New("revoked token")
	}
	buf := make([]byte, 8)
	copy(buf, dec[4:])
	return binary.LittleEndian.Uint64(buf), nil
}

func Revoke(token string) {
	revoked.Store(token, true)
	changed.Store(true)
	clean <- true
}

func RevokeAll() {
	key := make([]byte, 16)
	rand.Read(key)
	tokenKey.Store(key)
	revoked.Range(func(k, v any) bool {
		revoked.Delete(k)
		return true
	})
	changed.Store(true)
}

func Seed() []byte {
	return tokenKey.Load().([]byte)
}

func Init(seed []byte) (err error) {
	if len(seed) != 16 {
		return errors.New("length of seed must be 16 bytes")
	}
	tokenKey.Store(seed)
	changed.Store(true)
	return nil
}

func Revoked() []string {
	var rt []string
	revoked.Range(func(k, v any) bool {
		rt = append(rt, k.(string))
		return true
	})
	return rt
}

func Changed() bool {
	return changed.Load()
}

func Reset() {
	changed.Store(false)
}

var (
	tokenKey atomic.Value
	revoked  sync.Map
	clean    chan bool
	changed  atomic.Bool
)

func init() {
	clean = make(chan bool)
	RevokeAll()
	go func() {
		for {
			<-clean
			revoked.Range(func(k, v any) bool {
				if _, err := Verify(k.(string)); err != nil {
					revoked.Delete(k)
				}
				return true
			})
		}
	}()
}
