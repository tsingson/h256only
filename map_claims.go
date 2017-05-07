package h256only

import (
	"encoding/json"
	"errors"
	"time"
	// "fmt"
)

// Claims type that uses the map[string]interface{} for JSON decoding
// This is the default claims type if you don't supply one
type MapClaims map[string]interface{}

// Compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyAudience(cmp string, req bool) bool {
	aud, _ := m["aud"].(string)
	return verifyAud(aud, cmp, req)
}

// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyExpiresAt(cmp int64, req bool) bool {
	switch exp := m["exp"].(type) {
	case float64:
		return verifyExp(int64(exp), cmp, req)
	case int64:
		return verifyExp(exp, cmp, req)
	case json.Number:
		v, err := exp.Int64()
		if err != nil {
			return false
		}
		return verifyExp(v, cmp, req)
	}
	return req == false
}

// Compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuedAt(cmp int64, req bool) bool {
	switch iat := m["iat"].(type) {
	case float64:
		return verifyIat(int64(iat), cmp, req)
	case int64:
		return verifyIat(iat, cmp, req)
	case json.Number:
		v, err := iat.Int64()
		if err != nil {
			return false
		}
		return verifyIat(v, cmp, req)
	}
	return req == false
}

// Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyIssuer(cmp string, req bool) bool {
	iss, _ := m["iss"].(string)
	return verifyIss(iss, cmp, req)
}

// Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (m MapClaims) VerifyNotBefore(cmp int64, req bool) bool {
	switch nbf := m["nbf"].(type) {
	case float64:
		return verifyNbf(int64(nbf), cmp, req)
	case int64:
		return verifyNbf(nbf, cmp, req)
	case json.Number:
		v, err := nbf.Int64()
		if err != nil {
			return false
		}
		return verifyNbf(v, cmp, req)
	}
	return req == false
}

// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (m MapClaims) Valid() error {
	now := time.Now().Unix()

	if m.VerifyExpiresAt(now, false) == false {
		return errors.New("Token is expired")
	}

	if m.VerifyIssuedAt(now, false) == false {
		return errors.New("Token used before issued")
	}

	if m.VerifyNotBefore(now, false) == false {
		return errors.New("Token is not valid yet")
	}

	return nil
}
