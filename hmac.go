package h256only

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// Verify verifies that signingString was signed with signature and key. err
// will be nil if and only if the signingString matches the signature and key.
//
// Verify only checks the signature and makes no effort to ensure signingString
// is valid (e.g. is unexpired, has an 'alg' field) per the spec.
func Verify(signingString, signature string, key *[32]byte) error {
	if key == nil {
		panic("nil key")
	}
	// Decode signature, for comparison
	sig, err := DecodeSegment(signature)
	if err != nil {
		return err
	}

	// This signing method is symmetric, so we validate the signature
	// by reproducing the signature from the signing string and key, then
	// comparing that against the provided signature.
	hasher := hmac.New(sha256.New, (*key)[:])
	hasher.Write([]byte(signingString))
	if !hmac.Equal(sig, hasher.Sum(nil)) {
		return errors.New("invalid signature")
	}

	// No validation errors.  Signature is good.
	return nil
}

// Sign signs the string with the given key, then base 64 encodes the result and
// returns it. Sign makes no attempt to parse or validate signingString.
func Sign(signingString string, key *[32]byte) string {
	if key == nil {
		panic("nil key")
	}
	hasher := hmac.New(sha256.New, (*key)[:])
	hasher.Write([]byte(signingString))

	return EncodeSegment(hasher.Sum(nil))
}
