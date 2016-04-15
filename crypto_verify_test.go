package tweetnacl

import (
	"bytes"
	"math/rand"
	"testing"
)

// --- CryptoVerify16 ---

// Adapted from nacl/crypto_verify/try.c
func TestCryptoVerify16(t *testing.T) {
	x := make([]byte, 16)
	y := make([]byte, 16)

	for i := 0; i < ROUNDS; i++ {
		rand.Read(x)
		rand.Read(y)

		expected := bytes.Equal(x, y)
		verified, err := CryptoVerify16(x, y)

		if err != nil {
			t.Errorf("%v", err)
			return
		}

		if verified != expected {
			t.Errorf("[1] Invalid verify-16 result [%v][%v]", expected, verified)
			return
		}

		copy(y, x)
		verified, err = CryptoVerify16(x, y)

		if err != nil {
			t.Errorf("%v", err)
			return
		}

		if !verified {
			t.Errorf("[2] Invalid verify-16 result [%v][%v]", true, verified)
			return
		}

		for j := 0; j < 16; j++ {
			ix := rand.Intn(16)
			b := byte(rand.Intn(256))

			y[ix] = b
			expected := bytes.Equal(x, y)
			verified, err = CryptoVerify16(x, y)

			if err != nil {
				t.Errorf("%v", err)
				return
			}

			if verified != expected {
				t.Errorf("[3] Invalid verify-16 result [%v][%v]", expected, verified)
				return
			}
		}
	}
}

func BenchmarkCryptoVerify16(b *testing.B) {
	x := make([]byte, 16)
	y := make([]byte, 16)

	rand.Read(x)
	rand.Read(y)

	for i := 0; i < b.N; i++ {
		CryptoVerify16(x, y)
	}
}

// --- CryptoVerify32 ---

// Adapted from nacl/crypto_verify/try.c
func TestCryptoVerify32(t *testing.T) {
	x := make([]byte, 32)
	y := make([]byte, 32)

	for i := 0; i < ROUNDS; i++ {
		rand.Read(x)
		rand.Read(y)

		expected := bytes.Equal(x, y)
		verified, err := CryptoVerify32(x, y)

		if err != nil {
			t.Errorf("%v", err)
			return
		}

		if verified != expected {
			t.Errorf("[1] Invalid verify-32 result [%v][%v]", expected, verified)
			return
		}

		copy(y, x)
		verified, err = CryptoVerify32(x, y)

		if err != nil {
			t.Errorf("%v", err)
			return
		}

		if !verified {
			t.Errorf("[2] Invalid verify-32 result [%v][%v]", true, verified)
			return
		}

		for j := 0; j < 32; j++ {
			ix := rand.Intn(32)
			b := byte(rand.Intn(256))

			y[ix] = b
			expected := bytes.Equal(x, y)
			verified, err = CryptoVerify32(x, y)

			if err != nil {
				t.Errorf("%v", err)
				return
			}

			if verified != expected {
				t.Errorf("[3] Invalid verify-32 result [%v][%v]", expected, verified)
				return
			}
		}
	}
}

func BenchmarkCryptoVerify32(b *testing.B) {
	x := make([]byte, 32)
	y := make([]byte, 32)

	rand.Read(x)
	rand.Read(y)

	for i := 0; i < b.N; i++ {
		CryptoVerify32(x, y)
	}
}
