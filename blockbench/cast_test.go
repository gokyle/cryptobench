package blockbench

import "bytes"
import "fmt"
import "testing"

var cast5Key []byte

func TestCast5(t *testing.T) {
	key, ok := GenerateCast5Key()
	if !ok {
		fmt.Println("bench: Cast5 key generation failed")
		t.FailNow()
	}

	out, err := Cast5Encrypt(key, testdata)
	if err != nil {
		fmt.Printf("bench: Cast5 encrypt failed (%v)\n", err)
		t.FailNow()
	}

	msg, err := Cast5Decrypt(key, out)
	if err != nil {
		fmt.Printf("bench: Cast5 encrypt failed (%v)\n", err)
		t.FailNow()
	}

	if !bytes.Equal(msg, testdata) {
		fmt.Println("bench: Cast5 decrypt returned invalid plaintext")
		t.FailNow()
	}
}

func BenchmarkEncryptCast5CBC(b *testing.B) {
	b.StopTimer()
	var ok bool
	cast5Key, ok = GenerateCast5Key()
	if !ok {
		fmt.Println("Failed to generate Cast5 / HMAC-SHA-256 key.")
		b.FailNow()
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, err := Cast5Encrypt(cast5Key, testdata)
		if err != nil {
			fmt.Println("Encryption with Cast5-CBC failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}

func BenchmarkDecryptCast5CBC(b *testing.B) {
	b.StopTimer()
	out, err := Cast5Encrypt(cast5Key, testdata)
	if err != nil {
		fmt.Println("Encryption with Cast5-CBC failed.")
		b.FailNow()
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, err := Cast5Decrypt(cast5Key, out)
		if err != nil {
			fmt.Println("Decryption with Cast5-CBC failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}
