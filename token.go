package token

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"
)

func assert(e interface{}) {
	if e != nil {
		panic(e)
	}
}

func New(ident uint64, expire time.Time, owner net.IP) string {
	raw := []byte{0}
	rand.Read(raw)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(expire.Unix()))
	raw = append(raw, buf[2:]...)
	binary.BigEndian.PutUint64(buf, ident)
	raw = append(raw, buf...)
	raw = append(raw, raw[0])
	if owner != nil {
		raw = append(raw, owner.To16()...)
	}
	block, _ := aes.NewCipher(tokenKey)
	iv := bytes.Repeat([]byte{0}, aes.BlockSize)
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(raw, raw)
	return hex.EncodeToString(raw)
}

func Verify(token string, holder net.IP) (ident uint64, err error) {
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
	var owner net.IP
	switch len(data) {
	case 16:
	case 32:
		owner = net.IP(data[16:])
		data = data[:16]
	default:
		panic(fmt.Errorf("invalid data length (%d), expect 16 or 32", len(data)))
	}
	if data[0] != data[len(data)-1] {
		panic(errors.New("invalid head/tail"))
	}
	if len(owner) > 0 {
		if !bytes.Equal(owner, holder) {
			return 0, errors.New("illegal token")
		}
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
