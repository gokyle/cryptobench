package blockbench

import "crypto/rand"
import "fmt"
import "io"
import "io/ioutil"
import "testing"

var testdata []byte

func init() {
	var err error

	testdata, err = ioutil.ReadFile("testdata/test.dat")
	if err != nil {
		panic(err.Error())
	}
}

func TestREADME(t *testing.T) {
	fmt.Println(`

This is a set of benchmarks comparing various block ciphers' speed
at encrypting and decrypting a 4096-byte piece of data. This size
was chosen such that it was a realistic amount of data, but not so
large a message size as to doom each benchmark to being run only
once.

All of the benchmarks use appropriate authenticated symmetric
cryptography; that is, each block cipher is paired with an appropriate
MAC. In most cases, this is HMAC-SHA-384.

`)
}

func randBytes(in []byte) {
	_, err := io.ReadFull(rand.Reader, in)
	if err != nil {
		panic(err.Error())
	}
}
