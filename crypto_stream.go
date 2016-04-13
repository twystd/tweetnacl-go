package tweetnacl

/*
#include "tweetnacl.h"
*/
import "C"

import (
	"fmt"
)

// The number of bytes in the secret key for crypto_stream.
const STREAM_KEYBYTES int = 32

// The number of bytes in the nonce for crypto_stream.
const STREAM_NONCEBYTES int = 24

// The number of bytes in the secret key for crypto_stream_salsa20.
const STREAM_SALSA20_KEYBYTES int = 32

// The number of bytes in the nonce for crypto_stream_salsa20.
const STREAM_SALSA20_NONCEBYTES int = 8

// Wrapper function for crypto_stream.
//
// Generates a cipher stream of size 'length' as a function of the key and nonce.
//
// Ref. http://nacl.cr.yp.to/stream.html
func CryptoStream(length int, nonce, key []byte) ([]byte, error) {
	stream := make([]byte, length)
	N := (C.ulonglong)(length)

	rc := C.crypto_stream(makePtr(stream),
		N,
		makePtr(nonce),
		makePtr(key))

	if rc == 0 {
		return stream, nil
	}

	return nil, fmt.Errorf("Error generating cipher stream (error code %v)", rc)
}

// // Wrapper function for crypto_secretbox_open.
// //
// // Verifies and decrypts the ciphertext using the supplied secret key and nonce. The
// // The zero padding required by the crypto_secretbox C API is added internally and
// // should not be included in the supplied ciphertext. Likewise the zero padding that
// // prefixes the plaintext returned by the crypto_secretbox C API is stripped from the
// // returned plaintext.
// //
// // Ref. http://nacl.cr.yp.to/secretbox.html
// func CryptoSecretBoxOpen(ciphertext, nonce, key []byte) ([]byte, error) {
// 	buffer := make([]byte, len(ciphertext)+SECRETBOX_BOXZEROBYTES)
// 	N := (C.ulonglong)(len(buffer))
//
// 	copy(buffer[0:SECRETBOX_BOXZEROBYTES], BOX_PADDING)
// 	copy(buffer[SECRETBOX_BOXZEROBYTES:], ciphertext)
//
// 	rc := C.crypto_secretbox_open(makePtr(buffer),
// 		makePtr(buffer),
// 		N,
// 		makePtr(nonce),
// 		makePtr(key))
//
// 	if rc == 0 {
// 		return buffer[SECRETBOX_ZEROBYTES:], nil
// 	}
//
// 	return nil, fmt.Errorf("Error decrypting message (error code %v)", rc)
// }
