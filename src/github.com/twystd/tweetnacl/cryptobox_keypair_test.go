package tweetnacl

import (
	"fmt"
	"testing"
)

func TestCryptoBoxKeyPair(t *testing.T) {
	keypair, err := CryptoBoxKeyPair()

	if err != nil {
		t.Errorf("cryptobox_keypair: %v", err)
		return
	}

	if keypair == nil {
		t.Errorf("cryptobox_keypair: nil")
		return
	}

	if keypair.PublicKey == nil || len(keypair.PublicKey) != 32 {
		t.Errorf("cryptobox_keypair: invalid public key")
		return
	}

	if keypair.SecretKey == nil || len(keypair.SecretKey) != 32 {
		t.Errorf("cryptobox_keypair: invalid secret key")
		return
	}
}

func BenchmarkCryptoBoxKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CryptoBoxKeyPair()
	}
}

func ExampleCryptoBoxKeyPair() {
	keypair, err := CryptoBoxKeyPair()

	if err == nil {
		fmt.Printf("Public Key: %v", keypair.PublicKey)
		fmt.Printf("Secret Key: %v", keypair.SecretKey)
	}
}
