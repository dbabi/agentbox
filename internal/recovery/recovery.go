// Package recovery manages the offline LUKS recovery key pair.
//
// The installer encrypts the random LUKS keyfile to the RSA public key with
// RSA-OAEP-SHA256 (openssl pkeyutl -pkeyopt rsa_padding_mode:oaep -pkeyopt
// rsa_oaep_md:sha256, which also uses SHA-256 for MGF1). The private key never
// leaves the operator's machine.
package recovery

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// MinBits is the minimum accepted recovery key size.
const MinBits = 4096

// GenerateKey writes recovery.key (PKCS#8, mode 0600) and recovery.pub (PKIX)
// into dir. It refuses to overwrite an existing private key.
func GenerateKey(dir string) (privPath, pubPath string, err error) {
	privPath = filepath.Join(dir, "recovery.key")
	pubPath = filepath.Join(dir, "recovery.pub")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", err
	}
	// A directory others can write lets another local user swap recovery.pub before `agentbox seed` reads it.
	if fi, err := os.Lstat(dir); err != nil {
		return "", "", err
	} else if !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
		return "", "", fmt.Errorf("%s must be a real directory that only you can write (mode now %v)", dir, fi.Mode().Perm())
	}
	for _, p := range []string{privPath, pubPath} { // recovery.key is moved offline, so recovery.pub alone must not be replaced
		if _, err := os.Lstat(p); err == nil {
			return "", "", fmt.Errorf("%s already exists; refusing to overwrite recovery key material", p)
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, MinBits)
	if err != nil {
		return "", "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	// O_EXCL: never clobber a key created between the Stat above and here.
	f, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", "", err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: privDER}); err != nil {
		f.Close()
		return "", "", err
	}
	if err := f.Close(); err != nil {
		return "", "", err
	}
	pf, err := os.OpenFile(pubPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		os.Remove(privPath) // created above by this call; a lone private key would block every retry
		return "", "", err
	}
	_, err = pf.Write(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
	if cerr := pf.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(pubPath)
		os.Remove(privPath)
		return "", "", err
	}
	return privPath, pubPath, nil
}

// ParsePublic parses a PKIX PEM RSA public key of at least MinBits.
func ParsePublic(pemBytes []byte) (*rsa.PublicKey, error) {
	block, rest := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("recovery public key: expected a PEM \"PUBLIC KEY\" block")
	}
	if len(trimSpace(rest)) != 0 {
		return nil, errors.New("recovery public key: unexpected data after the PEM block")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("recovery public key: %w", err)
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("recovery public key: must be RSA")
	}
	if rk.N.BitLen() > 16384 {
		return nil, fmt.Errorf("recovery public key: %d bits is above the 16384-bit cap", rk.N.BitLen())
	}
	if rk.N.BitLen() < MinBits {
		return nil, fmt.Errorf("recovery public key: %d bits, need at least %d", rk.N.BitLen(), MinBits)
	}
	// e=1 makes RSA the identity, and an even or prime modulus is trivially invertible: recovery.bin would then
	// expose the LUKS key to anyone who reads /bootpart.
	if rk.E != 65537 || rk.N.Bit(0) == 0 || rk.N.ProbablyPrime(20) {
		return nil, errors.New("recovery public key: need e=65537 and an odd composite modulus")
	}
	return rk, nil
}

// Encrypt is the Go equivalent of the installer's openssl call (used in tests).
func Encrypt(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, plaintext, nil)
}

// Decrypt recovers the LUKS keyfile from recovery.bin.
func Decrypt(privPEM, ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("recovery private key: expected a PEM \"PRIVATE KEY\" block")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("recovery private key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("recovery private key: must be RSA")
	}
	return rsa.DecryptOAEP(sha256.New(), nil, rk, ciphertext, nil)
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\n' || b[0] == '\r' || b[0] == '\t') {
		b = b[1:]
	}
	return b
}
