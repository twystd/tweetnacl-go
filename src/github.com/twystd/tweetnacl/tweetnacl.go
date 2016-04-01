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
const crypto_box_PUBLICKEYBYTES int = 32

// The number of bytes in a crypto_box secret key
const crypto_box_SECRETKEYBYTES int = 32

// The number of zero padding bytes for a crypto_box message
const crypto_box_ZEROBYTES int = 32

// The number of zero padding bytes for a crypto_box ciphertext
const crypto_box_BOXZEROBYTES int = 16

// Constant zero-filled byte array used for padding messages
var crypto_box_PADDING = []byte{0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00}

type KeyPair struct {
	PublicKey []byte
	SecretKey []byte
}

// Wrapper function for crypto_box_keypair.
//
// Randomly generates a secret key and a corresponding public key. It guarantees that the secret key
// has crypto_box_PUBLICKEYBYTES bytes and that the public key has crypto_box_SECRETKEYBYTES bytes,
// returns a KeyPair initialised with a crypto_box public/private key pair.
//
// Ref. http://nacl.cr.yp.to/box.html
func CryptoBoxKeyPair() (*KeyPair, error) {
	pk := make([]byte, crypto_box_PUBLICKEYBYTES)
	sk := make([]byte, crypto_box_SECRETKEYBYTES)
	rc := C.crypto_box_keypair((*C.uchar)(unsafe.Pointer(&pk[0])), (*C.uchar)(unsafe.Pointer(&sk[0])))

	if rc == 0 {
		return &KeyPair{PublicKey: pk, SecretKey: sk}, nil
	}

	return nil, fmt.Errorf("Error generating key pair (error code %v)", rc)
}

// Wrapper function for crypto_box.
//
// Encrypts and authenticates the message using the secretKey, publicKey and nonce. The zero padding
// required by the crypto_box C API is added internally and should not be included in the supplied
// message. Likewise the zero padding that prefixes the ciphertext returned by the crypto_box C API
// is stripped from the returned ciphertext.
//
// Ref. http://nacl.cr.yp.to/box.html
func CryptoBox(message, nonce, publicKey, secretKey []byte) ([]byte, error) {
	plaintext := make([]byte, len(message)+crypto_box_ZEROBYTES)
	ciphertext := make([]byte, len(plaintext))

	copy(plaintext[0:32], crypto_box_PADDING)
	copy(plaintext[32:], message)

	rc := C.crypto_box((*C.uchar)(unsafe.Pointer(&ciphertext[0])),
		(*C.uchar)(unsafe.Pointer(&plaintext[0])),
		(C.ulonglong)(len(plaintext)),
		(*C.uchar)(unsafe.Pointer(&nonce[0])),
		(*C.uchar)(unsafe.Pointer(&publicKey[0])),
		(*C.uchar)(unsafe.Pointer(&secretKey[0])))

	if rc == 0 {
		return ciphertext[16:], nil
	}

	return nil, fmt.Errorf("Error encrypting message (error code %v)", rc)
}
