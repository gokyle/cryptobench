package blockbench

import "bytes"
import "fmt"
import "testing"

var tdesKey []byte

func Test3DES(t *testing.T) {
	key, ok := Generate3DESKey()
	if !ok {
		fmt.Println("bench: 3DES key generation failed")
		t.FailNow()
	}

	out, err := TDESEncrypt(key, testdata)
	if err != nil {
		fmt.Printf("bench: 3DES encrypt failed (%v)\n", err)
		t.FailNow()
	}

	msg, err := TDESDecrypt(key, out)
	if err != nil {
		fmt.Printf("bench: 3DES encrypt failed (%v)\n", err)
		t.FailNow()
	}

	if !bytes.Equal(msg, testdata) {
		fmt.Println("bench: 3DES decrypt returned invalid plaintext")
		t.FailNow()
	}
}

func BenchmarkEncrypt3DESEDECBC(b *testing.B) {
	b.StopTimer()
	var ok bool
	tdesKey, ok = Generate3DESKey()
	if !ok {
		fmt.Println("Failed to generate 3DES / HMAC-SHA-256 key.")
		b.FailNow()
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, err := TDESEncrypt(tdesKey, testdata)
		if err != nil {
			fmt.Println("Encryption with 3DES-EDE-CBC failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}

func BenchmarkDecrypt3DESEDECBC(b *testing.B) {
	b.StopTimer()
	out, err := TDESEncrypt(tdesKey, testdata)
	if err != nil {
		fmt.Println("Encryption with 3DES-EDE-CBC failed.")
		b.FailNow()
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, err := TDESDecrypt(tdesKey, out)
		if err != nil {
			fmt.Println("Decryption with 3DES-EDE-CBC failed.")
			b.FailNow()
		}
		b.SetBytes(int64(len(testdata)))
	}
}
