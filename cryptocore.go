package tweetnacl

/*
#include "tweetnacl.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// The number of bytes in an HSALSA20 intermediate key.
const crypto_core_HSALSA20_OUTPUTBYTES int = 32

// Wrapper function for crypto_core_hsalsa20.
//
// From the available documentation CryptoCoreHsalsa20 apparently calculates an
// intermediate key (from a secret key and shared secret) for encrypting and
// authenticating packets.
//
func CryptoCoreHSalsa20(in, key, constant []byte) ([]byte, error) {
	out := make([]byte, crypto_core_HSALSA20_OUTPUTBYTES)

	rc := C.crypto_core_hsalsa20((*C.uchar)(unsafe.Pointer(&out[0])),
		(*C.uchar)(unsafe.Pointer(&in[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
		(*C.uchar)(unsafe.Pointer(&constant[0])))

	if rc == 0 {
		return out, nil
	}

	return nil, fmt.Errorf("Error calculating intermediate key (error code %v)", rc)
}
