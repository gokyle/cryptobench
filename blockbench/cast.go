package blockbench

import (
	"code.google.com/p/go.crypto/cast5"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
)

func GenerateCast5Key() ([]byte, bool) {
	var key = make([]byte, cast5.KeySize+sha256.Size)
	_, err := io.ReadFull(rand.Reader, key)
	if err != nil {
		return nil, false
	}
	return key, true
}

func Cast5Encrypt(key []byte, msg []byte) (ct []byte, err error) {
	c, err := cast5.NewCipher(key[:cast5.KeySize])
	if err != nil {
		return
	}

	iv, err := GenerateCast5IV()
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
	ct = append(ct, cast5Tag(ct, key[cast5.KeySize:])...)
	return
}

func Cast5Decrypt(key []byte, ct []byte) (msg []byte, err error) {
	tag := ct[len(ct)-32:]
	ct = ct[:len(ct)-32]
	atag := cast5Tag(ct, key[cast5.KeySize:])
	if subtle.ConstantTimeCompare(tag, atag) != 1 {
		return nil, errors.New("decryption failure")
	}

	c, err := cast5.NewCipher(key[:cast5.KeySize])
	if err != nil {
		return
	}

	// Copy the ciphertext to prevent it from being modified.
	tmp_ct := make([]byte, len(ct))
	copy(tmp_ct, ct)
	iv := tmp_ct[:cast5.BlockSize]
	if len(iv) != cast5.BlockSize {
		return msg, ErrInvalidIV
	}
	msg = tmp_ct[cast5.BlockSize:]

	cbc := cipher.NewCBCDecrypter(c, iv)
	cbc.CryptBlocks(msg, msg)
	msg, err = cbcUnpadBuffer(msg)
	return
}

func cast5Tag(in []byte, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(in)
	return h.Sum(nil)
}

func GenerateCast5IV() (iv []byte, err error) {
	iv = make([]byte, cast5.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	return
}
