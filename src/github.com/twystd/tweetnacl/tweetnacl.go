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

// The number of zero padding bytes for a crypto_box message
const CRYPTO_BOX_ZEROBYTES int = 32

// The number of zero padding bytes for a crypto_box ciphertext
const CRYPTO_BOX_BOXZEROBYTES int = 16

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

	if rc == 0 {
		return &KeyPair{PublicKey: pk, SecretKey: sk}, nil
	}

	return nil, fmt.Errorf("Error generating key pair (error code %v)", rc)
}

func CryptoBox(message, nonce, publicKey, secretKey []byte) ([]byte, error) {
	plaintext := make([]byte, len(message)+CRYPTO_BOX_ZEROBYTES)
	ciphertext := make([]byte, len(plaintext))
	var index = 0

	for i := 0; i < CRYPTO_BOX_ZEROBYTES; i++ {
		plaintext[index] = 0
		index = index + 1
	}

	for i := 0; i < len(message); i++ {
		plaintext[index] = message[i]
		index = index + 1
	}

	rc := C.crypto_box((*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
		(C.ulonglong)(len(plaintext)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])))

	if rc == 0 {
		return ciphertext, nil
	}

	return nil, fmt.Errorf("Error encrypting message (error code %v)", rc)
}
