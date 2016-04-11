package tweetnacl

/*
#include "tweetnacl.h"
*/
import "C"

import (
	"fmt"
)

// The number of bytes in the authenticator.
const ONETIMEAUTH_BYTES int = 16

// The number of bytes in the secret key used to generate the authenticator.
const ONETIMEAUTH_KEYBYTES int = 32

// The number of bytes in the group element component of scalar multiplication.
const SCALARMULT_BYTES int = 32

// The number of bytes in the integer component of scalar multiplication.
const SCALARMULT_SCALARBYTES int = 32

// Wrapper function for crypto_onetimeauth.
//
// Uses the supplied secret key to calculate an authenticator for the message.
//
// Ref. http://nacl.cr.yp.to/onetimeauth.html
func CryptoOneTimeAuth(message, key []byte) ([]byte, error) {
	authenticator := make([]byte, ONETIMEAUTH_BYTES)
	N := (C.ulonglong)(len(message))

	rc := C.crypto_onetimeauth(makePtr(authenticator),
		makePtr(message),
		N,
		makePtr(key))

	if rc == 0 {
		return authenticator, nil
	}

	return nil, fmt.Errorf("Error calculating one time authenticator (error code %v)", rc)
}

// Wrapper function for crypto_onetimeauth_verify.
//
// Uses the supplied secret key to verify the authenticator for the message.
//
// Ref. http://nacl.cr.yp.to/onetimeauth.html
func CryptoOneTimeAuthVerify(authenticator, message, key []byte) (bool, error) {
	N := (C.ulonglong)(len(message))

	rc := C.crypto_onetimeauth_verify(makePtr(authenticator),
		makePtr(message),
		N,
		makePtr(key))

	if rc == 0 {
		return true, nil
	}

	return false, fmt.Errorf("Error calculating one time authenticator (error code %v)", rc)
}

// Wrapper function for crypto_scalarmult_base.
//
// Computes the scalar product of a standard group element and an integer.
//
// Ref. http://nacl.cr.yp.to/onetimeauth.html
func CryptoScalarMult(n, p []byte) ([]byte, error) {
	q := make([]byte, SCALARMULT_BYTES)
	rc := C.crypto_scalarmult(makePtr(q), makePtr(n), makePtr(p))

	if rc == 0 {
		return q, nil
	}

	return nil, fmt.Errorf("Error calculating scalar multiplication (error code %v)", rc)
}
