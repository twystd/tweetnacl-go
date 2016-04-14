package tweetnacl

import (
	"testing"
)

// --- CryptoSignKeyPair ---

// Adapted from tests/core1.c)
func TestCryptoSignKeyPair(t *testing.T) {
	keypair, err := CryptoSignKeyPair()

	if err != nil {
		t.Errorf("crypto_sign_keypair: %v", err)
		return
	}

	if keypair.PublicKey == nil || len(keypair.PublicKey) != SIGN_PUBLICKEYBYTES {
		t.Errorf("crypto_sign_keypair: invalid public key")
		return
	}

	if keypair.SecretKey == nil || len(keypair.SecretKey) != SIGN_SECRETKEYBYTES {
		t.Errorf("crypto_sign_keypair: invalid secret key")
		return
	}
}

func BenchmarkCryptoSignKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		CryptoSignKeyPair()
	}
}
