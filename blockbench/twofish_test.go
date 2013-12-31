package blockbench

import "fmt"
import "github.com/cryptobox/twofishbox"
import "testing"

// twofishbox uses Twofish-256 in CTR mode with HMAC-SHA-384.

var (
	twofishboxKey []byte
)

func BenchmarkEncryptTwofish256CTR(b *testing.B) {
	b.StopTimer()
	var ok bool
	twofishboxKey, ok = twofishbox.GenerateKey()
	if !ok {
		fmt.Println("Failed to generate Twofish-256 / HMAC-SHA-384 key.")
		b.FailNow()
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, ok = twofishbox.Seal(testdata, twofishboxKey)
		if !ok {
			fmt.Println("Encryption with Twofish-256 CTR / HMAC-SHA-384 failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}

func BenchmarkDecryptTwofish256CTR(b *testing.B) {
	b.StopTimer()
	box, ok := twofishbox.Seal(testdata, twofishboxKey)
	if !ok {
		fmt.Println("Encryption with Twofish-256 CTR / HMAC-SHA-384 failed.")
		b.FailNow()
	}

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, ok := twofishbox.Open(box, twofishboxKey)
		if !ok {
			fmt.Println("Decryption with Twofish-256 CTR / HMAC-SHA-384 failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}
