package tweetnacl

/*
#include "tweetnacl.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// The number of bytes in the authenticator.
const ONETIMEAUTH_BYTES int = 16

// The number of bytes in the secret key used to generate the authenticator.
const ONETIMEAUTH_KEYBYTES int = 32

// Wrapper function for crypto_onetimeauth.
//
// Uses the supplied secret key to calculate an authenticator for the message.
//
// Ref. http://nacl.cr.yp.to/onetimeauth.html
func CryptoOneTimeAuth(message, key []byte) ([]byte, error) {
	authenticator := make([]byte, ONETIMEAUTH_BYTES)
	N := len(message)

	rc := C.crypto_onetimeauth((*C.uchar)(unsafe.Pointer(&authenticator[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(C.ulonglong)(N),
		(*C.uchar)(unsafe.Pointer(&key[0])))

	if rc == 0 {
		return authenticator, nil
	}

	return nil, fmt.Errorf("Error calculating one time authenticator (error code %v)", rc)
}
