package blockbench

// this file implements 3DES-EDE-CBC

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
)

func Generate3DESKey() ([]byte, bool) {
	var key = make([]byte, 24+32)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, false
	}
	return key, true
}

func cbcPadBuffer(m []byte) (p []byte, err error) {
	mLen := len(m)

	padding := des.BlockSize - mLen%des.BlockSize
	p = make([]byte, mLen, mLen+padding)
	copy(p, m)
	p = append(p, 0x80)
	for i := 1; i < padding; i++ {
		p = append(p, 0x0)
	}
	return
}

func cbcUnpadBuffer(p []byte) (m []byte, err error) {
	m = p
	var pLen int
	origLen := len(m)

	for pLen = origLen - 1; pLen >= 0; pLen-- {
		if m[pLen] == 0x80 {
			break
		}

		if m[pLen] != 0x0 || (origLen-pLen) > des.BlockSize {
			err = errors.New("invalid CBC padding")
			return
		}
	}
	m = m[:pLen]
	return
}

// Generate a suitable initialisation vector.
func Generate3DESIV() (iv []byte, err error) {
	iv = make([]byte, des.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	return
}

func TDESEncrypt(key []byte, msg []byte) (ct []byte, err error) {
	c, err := des.NewTripleDESCipher(key[:24])
	if err != nil {
		return
	}

	iv, err := Generate3DESIV()
	if err != nil {
		return
	}

	padded, err := cbcPadBuffer(msg)
	if err != nil {
		return
	}

	cbc := cipher.NewCBCEncrypter(c, iv)
	cbc.CryptBlocks(padded, padded) // encrypt in-place
	ct = iv
	ct = append(ct, padded...)
	ct = append(ct, tdesTag(ct, key[24:])...)
	return
}

var ErrInvalidIV = fmt.Errorf("invalid IV")

func TDESDecrypt(key []byte, ct []byte) (msg []byte, err error) {
	tag := ct[len(ct)-32:]
	ct = ct[:len(ct)-32]
	atag := tdesTag(ct, key[24:])
	if subtle.ConstantTimeCompare(tag, atag) != 1 {
		return nil, errors.New("decryption failure")
	}

	c, err := des.NewTripleDESCipher(key[:24])
	if err != nil {
		return
	}

	// Copy the ciphertext to prevent it from being modified.
	tmp_ct := make([]byte, len(ct))
	copy(tmp_ct, ct)
	iv := tmp_ct[:des.BlockSize]
	if len(iv) != des.BlockSize {
		return msg, ErrInvalidIV
	}
	msg = tmp_ct[des.BlockSize:]

	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(msg, msg)
	msg, err = cbcUnpadBuffer(msg)
	return
}

func tdesTag(in []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(in)
	return h.Sum(nil)
}
