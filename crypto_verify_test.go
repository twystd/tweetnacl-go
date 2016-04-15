package tweetnacl

import (
	"bytes"
	"math/rand"
	"testing"
)

// --- CryptoVerify16 ---

// Adapted from http://ed25519.cr.yp.to/python/sign.py.
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

func BenchmarkCryptoVerify(b *testing.B) {
	x := make([]byte, 16)
	y := make([]byte, 16)

	rand.Read(x)
	rand.Read(y)

	for i := 0; i < b.N; i++ {
		CryptoVerify16(x, y)
	}
}
