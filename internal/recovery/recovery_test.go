package recovery

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestKeygenEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	privPath, pubPath, err := GenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(privPath); fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v, want 0600", fi.Mode().Perm())
	}
	pubPEM, _ := os.ReadFile(pubPath)
	pub, err := ParsePublic(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("012345678901234567890123456789012345678901234567") // installer keyfile: 48 ASCII digits, no newline
	ct, err := Encrypt(pub, secret)
	if err != nil {
		t.Fatal(err)
	}
	privPEM, _ := os.ReadFile(privPath)
	got, err := Decrypt(privPEM, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("round trip mismatch")
	}
	if _, _, err := GenerateKey(dir); err == nil {
		t.Fatal("GenerateKey overwrote an existing key")
	}
}

func TestParsePublicRejectsWeakAndJunk(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	weak := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := ParsePublic(weak); err == nil {
		t.Fatal("accepted a 2048-bit key")
	}
	if _, err := ParsePublic([]byte("not a key")); err == nil {
		t.Fatal("accepted junk")
	}
	if _, err := ParsePublic(append(weak, []byte("trailing")...)); err == nil {
		t.Fatal("accepted trailing data")
	}
}

// TestOpenSSLInterop proves the installer's exact openssl invocation decrypts
// with Decrypt. Skips when the local openssl lacks OAEP-SHA256 (e.g. LibreSSL).
func TestOpenSSLInterop(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	dir := t.TempDir()
	privPath, pubPath, err := GenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(dir, "luks.key")
	secret := []byte("012345678901234567890123456789012345678901234567")
	os.WriteFile(in, secret, 0o600)
	out := filepath.Join(dir, "recovery.bin")
	cmd := exec.Command(openssl, "pkeyutl", "-encrypt", "-pubin", "-inkey", pubPath,
		"-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256", "-in", in, "-out", out)
	if msg, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("local openssl can't do OAEP-SHA256: %s", bytes.TrimSpace(msg))
	}
	ct, _ := os.ReadFile(out)
	privPEM, _ := os.ReadFile(privPath)
	got, err := Decrypt(privPEM, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("openssl ciphertext did not decrypt to the original key")
	}
}

func TestParsePublicRejectsInvertibleKeys(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 4096)
	enc := func(pk *rsa.PublicKey) []byte {
		der, err := x509.MarshalPKIXPublicKey(pk)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	}
	for _, e := range []int{1, 2, 3} {
		pk := k.PublicKey
		pk.E = e
		if _, err := ParsePublic(enc(&pk)); err == nil {
			t.Errorf("accepted e=%d", e)
		}
	}
	even := k.PublicKey
	even.N = new(big.Int).Lsh(k.Primes[0], 1) // 2*p: even
	even.N.Mul(even.N, k.Primes[1])
	if _, err := ParsePublic(enc(&even)); err == nil {
		t.Error("accepted an even modulus")
	}
	prime := k.PublicKey
	for p := new(big.Int).Lsh(big.NewInt(1), 4095).Add(new(big.Int).Lsh(big.NewInt(1), 4095), big.NewInt(1)); ; p.Add(p, big.NewInt(2)) {
		if p.ProbablyPrime(20) {
			prime.N = p
			break
		}
	}
	if _, err := ParsePublic(enc(&prime)); err == nil {
		t.Error("accepted a prime modulus")
	}
}

func TestGenerateKeyKeepsPublicKey(t *testing.T) {
	dir := t.TempDir()
	priv, pub, err := GenerateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(pub)
	os.Remove(priv) // the operator moved recovery.key offline
	if _, _, err := GenerateKey(dir); err == nil {
		t.Fatal("GenerateKey replaced recovery.pub")
	}
	if after, _ := os.ReadFile(pub); !bytes.Equal(before, after) {
		t.Fatal("recovery.pub changed")
	}
	if _, err := os.Stat(priv); err == nil {
		t.Fatal("a failed GenerateKey left a private key behind")
	}
}

func TestGenerateKeyRefusesSharedDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, _, err := GenerateKey(dir); err == nil {
		t.Fatal("GenerateKey accepted a world-writable directory")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("GenerateKey wrote into the shared directory")
	}
}
