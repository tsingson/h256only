package h256only

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// A Token.
type Token struct {
	Raw       string                 // The raw token. Populated when you Parse a token
	Header    map[string]interface{} // The first segment of the token
	Claims    Claims                 // The second segment of the token
	Signature string                 // The third segment of the token.  Populated when you Parse a token
}

// Create a new Token.
func New() *Token {
	return NewWithClaims(MapClaims{})
}

func NewWithClaims(claims Claims) *Token {
	return &Token{
		Header: map[string]interface{}{
			"typ": "h256only",
		},
		Claims: claims,
	}
}

// Get the complete, signed token
func (t *Token) SignedString(key *[32]byte) (string, error) {
	sstr, err := t.signingString()
	if err != nil {
		return "", err
	}
	sig := Sign(sstr, key)
	return strings.Join([]string{sstr, sig}, "."), nil
}

// JSON encode the header and the claims and join them with a period. Any
// Marshal error will be returned.
func (t *Token) signingString() (string, error) {
	var err error
	parts := make([]string, 2)
	bits, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}
	parts[0] = EncodeSegment(bits)
	bits2, err2 := json.Marshal(t.Claims)
	if err2 != nil {
		return "", err2
	}
	parts[1] = EncodeSegment(bits2)
	return strings.Join(parts, "."), nil
}

// Encode JWT specific base64url encoding with padding stripped
func EncodeSegment(seg []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(seg), "=")
}

// Decode JWT specific base64url encoding with padding stripped
func DecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
