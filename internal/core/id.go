package core

import (
	"crypto/rand"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewID returns prefix + "_" + a ULID (48-bit millisecond timestamp followed by
// 80 random bits, Crockford base32), e.g. "req_01J9Z3K4...".
func NewID(prefix string) string {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	if _, err := rand.Read(b[6:]); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	// 128 bits -> 26 base32 characters; the first character holds 3 bits.
	out := make([]byte, 26)
	var acc uint64
	var bits uint
	pos := 25
	for i := 15; i >= 0; i-- {
		acc |= uint64(b[i]) << bits
		bits += 8
		for bits >= 5 {
			out[pos] = crockford[acc&31]
			pos--
			acc >>= 5
			bits -= 5
		}
	}
	out[0] = crockford[acc&31]
	return prefix + "_" + string(out)
}
