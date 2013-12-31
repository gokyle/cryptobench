package blockbench

import "fmt"
import "github.com/cryptobox/gocryptobox/strongbox"
import "github.com/cryptobox/xtsbox"
import "github.com/cryptobox/gcmbox"
import "testing"

// strongbox uses AES-256 in CTR mode with HMAC-SHA-384.

var (
	strongboxKey []byte
	xtsboxKey    xtsbox.Key
	xtsboxTweak  uint64
	gcmboxKey    []byte
)

func BenchmarkEncryptAES256CTR(b *testing.B) {
	b.StopTimer()
	var ok bool
	strongboxKey, ok = strongbox.GenerateKey()
	if !ok {
		fmt.Println("Failed to generate AES-256 / HMAC-SHA-384 key.")
		b.FailNow()
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, ok = strongbox.Seal(testdata, strongboxKey)
		if !ok {
			fmt.Println("Encryption with AES-256 CTR / HMAC-SHA-384 failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}

func BenchmarkDecryptAES256CTR(b *testing.B) {
	b.StopTimer()
	box, ok := strongbox.Seal(testdata, strongboxKey)
	if !ok {
		fmt.Println("Encryption with AES-256 CTR / HMAC-SHA-384 failed.")
		b.FailNow()
	}

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, ok := strongbox.Open(box, strongboxKey)
		if !ok {
			fmt.Println("Decryption with AES-256 CTR / HMAC-SHA-384 failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}

func BenchmarkEncryptAES256XTS(b *testing.B) {
	b.StopTimer()
	var ok bool
	var err error

	xtsboxKey, ok = xtsbox.GenerateKey()
	if !ok {
		fmt.Println("Failed to generate AES-256 / HMAC-SHA-384 key.")
		b.FailNow()
	}

	xtsboxTweak, err = xtsbox.RandTweak()
	if err != nil {
		fmt.Println("Failed to generate random tweak for AES-XTS.")
		b.FailNow()
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, ok = xtsbox.Seal(xtsboxKey, testdata, xtsboxTweak)
		if !ok {
			fmt.Println("Encryption with AES-256 XTS / HMAC-SHA-384 failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}

func BenchmarkDecryptAES256XTS(b *testing.B) {
	b.StopTimer()
	box, ok := xtsbox.Seal(xtsboxKey, testdata, xtsboxTweak)
	if !ok {
		fmt.Println("Encryption with AES-256 XTS / HMAC-SHA-384 failed.")
		b.FailNow()
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, ok = xtsbox.Open(xtsboxKey, box, xtsboxTweak)
		if !ok {
			fmt.Println("Decryption with AES-256 XTS / HMAC-SHA-384 failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}

func BenchmarkEncryptAES256GCM(b *testing.B) {
	b.StopTimer()
	var ok bool
	gcmboxKey, ok = gcmbox.GenerateKey()
	if !ok {
		fmt.Println("Failed to generate AES-256 GCM key.")
		b.FailNow()
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, ok = gcmbox.Seal(testdata, gcmboxKey)
		if !ok {
			fmt.Println("Encryption with AES-256 GCM failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}

func BenchmarkDecryptAES256GCM(b *testing.B) {
	b.StopTimer()
	box, ok := gcmbox.Seal(testdata, gcmboxKey)
	if !ok {
		fmt.Println("Encryption with AES-256 GCM failed.")
		b.FailNow()
	}

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, ok := gcmbox.Open(box, gcmboxKey)
		if !ok {
			fmt.Println("Decryption with AES-256 GCM failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}
