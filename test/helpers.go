package test

import (
	"github.com/kevinburke/h256only"
)

func MakeSampleToken(c h256only.Claims, key *[32]byte) string {
	token := h256only.NewWithClaims(c)
	s, e := token.SignedString(key)

	if e != nil {
		panic(e.Error())
	}

	return s
}
