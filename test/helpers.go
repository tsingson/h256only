package test

import (
	"github.com/tsingson/h256only"
)

func MakeSampleToken(c interface{}, key *[32]byte) string {
	token := h256only.NewWithClaims(c)
	s, e := token.SignedString(key)

	if e != nil {
		panic(e.Error())
	}

	return s
}
