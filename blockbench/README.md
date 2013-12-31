## blockbench
A benchmark of various implementations of block ciphers as implemented in Go.

Each tested encryption scheme uses proper authenticated symmetric
cryptography; where AEAD is not available, an appropriate MAC is
appended and encryption/decryption is done using encrypt-then-MAC.

### Benchmarked Ciphers

* AES-256 in CTR mode with HMAC-SHA-384 (as provided by
[strongbox](http://godoc.org/github.com/cryptobox/gocryptobox/strongbox);
this is the current recommended cipher via *Cryptography Engineering*.
This is a 256-bit block cipher using a 32-byte encryption key and
a 48-byte MAC key.

* AES-256 in XTS mode with HMAC-SHA-384 (as provided by
[xtsbox](http://godoc.org/github.com/cryptobox/xtsbox). This is a
common cipher for disk encryption. This is a 256-bit block cipher
using a 32-byte encryption key and a 48-byte MAC key.

* AES-256 in GCM mode (as provided by
[gcmbox](http://godoc.org/github.com/cryptobox/gcmbox)). This uses
authenticated encryption with additional data (AEAD), and therefore
doesn't require an appended MAC. This is a 256-bit block cipher
using a 32-byte encryption key.

* Cast5 in CBC mode with HMAC-SHA-384 (as provided by an internal
implementation in cast5.go using the extended Go crypto library).
This is a common PGP block cipher; it is a 128-bit block cipher
using a 16-byte encryption key and a 32-byte MAC key.

* Salsa/20 with Poly1305 (as provided by NaCl's
[secretbox](http://godoc.org/code.google.com/p/go.crypto/nacl/secretbox)).
This is an alternate cipher used by many people distrustful of AES
and the NIST recommendations. This is a 128-bit block cipher using
a 16-byte encryption key and a 16-byte MAC key.

* 3DES-EDE-CBC with HMAC-SHA-256 (as provided by an internal
implementation in tdes.go using the standard library). This cipher
should never be used in new designs, but might be required for
compatibility reasons. This is a 168-bit block cipher uses a 24-byte
encryption key and a 32-byte MAC key.

* Twofish-256 in CTR mode with HMAC-SHA-384 (as provided by
[twofishbox](http://godoc.org/github.com/cryptobox/twofishbox));
Twofish is an alternate AES finalist designed by, among others,
Niels Ferguson and Bruce Schneier. It provides a slower, but more
conservative, block cipher. This is a 256-bit block cipher that
uses a 32-byte encryption key and a 48-byte MAC key.

### Running the benchmarks

	$ go test -test.bench='.+'

The benchmarks will report time in nanoseconds per operation, as
well as amount of data encrypted or decrypted per second.

The only actual tests in the package consist of tests on the 3DES
encryption scheme used. A dummy test prints a message about the
purpose of the package.


### Motivation

I was curious to see how Go's implementations of XTS and GCM mode
fared, as well as how the Twofish implementation compared to other
ciphers.
