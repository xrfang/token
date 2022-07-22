package token

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"time"
)

func assert(e interface{}) {
	if e != nil {
		panic(e)
	}
}

func New(ident uint64, expire time.Time) string {
	raw := []byte{0}
	rand.Read(raw)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(expire.Unix()))
	raw = append(raw, buf[2:]...)
	binary.BigEndian.PutUint64(buf, ident)
	raw = append(raw, buf...)
	raw = append(raw, raw[0])
	block, _ := aes.NewCipher(tokenKey)
	iv := bytes.Repeat([]byte{0}, aes.BlockSize)
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(raw, raw)
	return hex.EncodeToString(raw)
}

func Verify(token string) (ident uint64, err error) {
	defer func() {
		if e := recover(); e != nil {
			err = errors.New("corrupted token")
		}
	}()
	data, err := hex.DecodeString(token)
	assert(err)
	block, _ := aes.NewCipher(tokenKey)
	iv := bytes.Repeat([]byte{0}, aes.BlockSize)
	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(data, data)
	if data[0] != data[len(data)-1] {
		panic(errors.New("invalid head/tail"))
	}
	timestamp := binary.BigEndian.Uint64(append([]byte{0, 0}, data[1:7]...))
	exp := time.Unix(int64(timestamp), 0)
	if time.Now().After(exp) {
		return 0, errors.New("invalid token")
	}
	return binary.BigEndian.Uint64(data[7:]), nil
}

var tokenKey []byte

func init() {
	tokenKey = make([]byte, 16)
	rand.Read(tokenKey)
}
