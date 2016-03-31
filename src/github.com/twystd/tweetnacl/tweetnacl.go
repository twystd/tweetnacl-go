package tweetnacl

/*
#include "tweetnacl.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// The number of bytes in a crypto_box public key
const CRYPTO_BOX_PUBLICKEYBYTES int = 32

// The number of bytes in a crypto_box secret key
const CRYPTO_BOX_SECRETKEYBYTES int = 32

type KeyPair struct {
	PublicKey []byte
	SecretKey []byte
}

// Wrapper function for crypto_box_keypair.
//
// Randomly generates a secret key and a corresponding public key. It guarantees that the secret key
// has CRYPTO_BOX_PUBLICKEYBYTES bytes and that the public key has CRYPTO_BOX_SECRETKEYBYTES bytes,
// returns a KeyPair initialised with a crypto_box public/private key pair.
//
// Ref. http://nacl.cr.yp.to/box.html
func CryptoBoxKeyPair() (*KeyPair, error) {
	pk := make([]byte, CRYPTO_BOX_PUBLICKEYBYTES)
	sk := make([]byte, CRYPTO_BOX_SECRETKEYBYTES)
	rc := C.crypto_box_keypair((*C.uchar)(unsafe.Pointer(&pk[0])), (*C.uchar)(unsafe.Pointer(&sk[0])))

	if rc == 1 {
		return &KeyPair{PublicKey: pk, SecretKey: sk}, nil
	}

	return nil, fmt.Errorf("Error generating key pair (error code %v)", rc)
}
