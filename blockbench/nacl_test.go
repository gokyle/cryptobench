package blockbench

import nacl "code.google.com/p/go.crypto/nacl/secretbox"
import "fmt"
import "testing"

var (
	naclKey   [32]byte
	naclNonce [24]byte
)

// The nonce is reused as this is a benchmark and the encrypted
// message is discarded.

func BenchmarkEncryptSalsa20Poly1305(b *testing.B) {
	b.StopTimer()
	randBytes(naclKey[:])
	randBytes(naclNonce[:])
	var out []byte
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_ = nacl.Seal(out, testdata, &naclNonce, &naclKey)
		b.SetBytes(int64(len(testdata)))
	}
}

func BenchmarkDecryptSalsa20Poly1305(b *testing.B) {
	b.StopTimer()
	out := nacl.Seal(nil, testdata, &naclNonce, &naclKey)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, ok := nacl.Open(nil, out, &naclNonce, &naclKey)
		if !ok {
			fmt.Println("Decryption with XSalsa20 / Poly1305 failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}
