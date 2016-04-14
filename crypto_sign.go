package tweetnacl

/*
#include "tweetnacl.h"
*/
import "C"

import (
	"fmt"
)

// The number of bytes added to a message for a signature.
const SIGN_BYTES int = 64

// The number of bytes in a signing key pair public key.
const SIGN_PUBLICKEYBYTES int = 32

// The number of bytes in a signing key pair secret key.
const SIGN_SECRETKEYBYTES int = 64

// The number of bytes in a secret for the crypto_verify_16 function.
const VERIFY16_BYTES int = 16

// The number of bytes in a secret for the crypto_verify_32 function.
const VERIFY32_BYTES int = 32

// Wrapper function for crypto_sign_keypair.
//
// Randomly generates a secret key and corresponding public key.
//
// Ref. http://nacl.cr.yp.to/sign.html
func CryptoSignKeyPair() (*KeyPair, error) {
	pk := make([]byte, SIGN_PUBLICKEYBYTES)
	sk := make([]byte, SIGN_SECRETKEYBYTES)

	rc := C.crypto_sign_keypair(makePtr(pk), makePtr(sk))

	if rc == 0 {
		return &KeyPair{PublicKey: pk, SecretKey: sk}, nil
	}

	return nil, fmt.Errorf("Error generating signing key pair (error code %v)", rc)
}
