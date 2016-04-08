package tweetnacl

/*
#include "tweetnacl.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// The number of bytes returned by CryptHash.
const crypto_hash_HASH_BYTES int = 64

// The size of the state byte array for crypto_hashblocks.
const crypto_hash_HASHBLOCKS_STATEBYTES int = 64

// The block size for the message for crypto_hashblocks.
const crypto_hash_HASHBLOCKS_BLOCKBYTES int = 128

// Wrapper function for crypto_hash.
//
// Calculates a SHA-512 hash of the message.
//
// Ref. http://nacl.cr.yp.to/hash.html
func CryptoHash(message []byte) ([]byte, error) {
	hash := make([]byte, crypto_hash_HASH_BYTES)
	N := len(message)

	rc := C.crypto_hash((*C.uchar)(unsafe.Pointer(&hash[0])),
		(*C.uchar)(unsafe.Pointer(&message[0])),
		(C.ulonglong)(N))

	if rc == 0 {
		return hash, nil
	}

	return nil, fmt.Errorf("Error calculating SHA-512 hash (error code %v)", rc)
}

// Wrapper function for crypto_hashblocks.
//
// Undocumented anywhere, but seems to be a designed to calculate the SHA-512 hash of
// a stream of blocks. Each block must be a multiple of 128 bytes and the returned
// hash from each call should be recycled into the next (see example).
//
// Ref. http://nacl.cr.yp.to/hash.html
func CryptoHashBlocks(iv, blocks []byte) ([]byte, error) {
	hash := make([]byte, crypto_hash_HASHBLOCKS_STATEBYTES)
	N := len(blocks)

	copy(hash, iv)

	rc := C.crypto_hashblocks((*C.uchar)(unsafe.Pointer(&hash[0])),
		(*C.uchar)(unsafe.Pointer(&blocks[0])),
		(C.ulonglong)(N))

	if rc == 0 {
		return hash, nil
	}

	return nil, fmt.Errorf("Error calculating running SHA-512 hash (error code %v)", rc)
}
