package h256only

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Parse, validate, and return a token.
// keyFunc will receive the parsed token and should return the key for validating.
func Parse(tokenString string, key *[32]byte) (*Token, error) {
	return ParseWithClaims(tokenString, MapClaims{}, key)
}

func ParseWithClaims(tokenString string, claims Claims, key *[32]byte) (*Token, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("token contains an invalid number of segments")
	}

	var err error
	token := &Token{Raw: tokenString}

	// parse Header
	var headerBytes []byte
	if headerBytes, err = DecodeSegment(parts[0]); err != nil {
		if strings.HasPrefix(strings.ToLower(tokenString), "bearer ") {
			return nil, errors.New("tokenstring should not contain 'bearer '")
		}
		return nil, err
	}
	if err = json.Unmarshal(headerBytes, &token.Header); err != nil {
		return nil, err
	}

	// parse Claims
	var claimBytes []byte
	token.Claims = claims

	if claimBytes, err = DecodeSegment(parts[1]); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(claimBytes))
	dec.UseNumber()
	if c, ok := token.Claims.(MapClaims); ok {
		err = dec.Decode(&c)
	} else {
		err = dec.Decode(&claims)
	}
	// Handle decode error
	if err != nil {
		return nil, err
	}

	// Lookup signature method
	if _, ok := token.Header["alg"].(string); ok {
		return nil, errors.New("'alg' parameter is illegal; there is only one supported algorithm")
	}
	typ, ok := token.Header["typ"].(string)
	if !ok {
		return nil, errors.New("no 'typ' parameter in header")
	}
	if typ != "h256only" {
		return nil, fmt.Errorf("unknown type '%s'")
	}

	// Validate Claims
	if err := token.Claims.Valid(); err != nil {
		return nil, err
	}

	// Perform validation
	token.Signature = parts[2]
	if err = Verify(strings.Join(parts[0:2], "."), token.Signature, key); err != nil {
		return nil, err
	}

	return token, nil
}
