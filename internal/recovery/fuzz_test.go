package recovery

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// Fuzz targets for the recovery key formats: the public key `agentbox seed` reads, and the private key and recovery.bin
// (on the unencrypted /bootpart) that `agentbox recovery decrypt` reads (issue #10).

func FuzzParsePublic(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, MinBits)
	if err != nil {
		f.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	f.Add(p)
	f.Add(append(p, "\n-----BEGIN PUBLIC KEY-----\n"...))
	f.Add([]byte("-----BEGIN PUBLIC KEY-----\nMAA=\n-----END PUBLIC KEY-----\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		k, err := ParsePublic(b)
		if err != nil {
			return
		}
		if k.E != 65537 || k.N.BitLen() < MinBits || k.N.BitLen() > 16384 || k.N.Bit(0) == 0 {
			t.Fatalf("accepted e=%d, %d bits", k.E, k.N.BitLen())
		}
	})
}

func FuzzDecrypt(f *testing.F) {
	key, err := rsa.GenerateKey(rand.Reader, 2048) // the format, not the size, is under test: keeps execs fast
	if err != nil {
		f.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	priv := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	ct, err := Encrypt(&key.PublicKey, []byte("012345678901234567890123456789012345678901234567"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(priv, ct)
	f.Add(priv, ct[:10])
	f.Add([]byte("-----BEGIN PRIVATE KEY-----\nMAA=\n-----END PRIVATE KEY-----\n"), ct)
	f.Fuzz(func(t *testing.T, priv, ct []byte) {
		Decrypt(priv, ct)
	})
}
