package h256only_test

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/tsingson/h256only"
	"github.com/tsingson/h256only/test"
)

var testData = []struct {
	name        string
	tokenString string
	claims      interface{}
	err         string
}{
	{
		"basic",
		"eyJ0eXAiOiJoMjU2b25seSJ9.eyJmb28iOiJiYXIifQ.Rw_hYjKT1nbhuvLfPJknTXv7P-QJFwEKWroE3NNZWRo",
		h256only.MapClaims{"foo": "bar"},
		"",
	},
	{
		"basic wrongkey",
		"eyJ0eXAiOiJoMjU2b25seSJ9.eyJmb28iOiJiYXIifQ.wrongsignature",
		h256only.MapClaims{"foo": "bar"},
		"invalid signature",
	},
	{
		"valid signing method",
		"",
		h256only.MapClaims{"foo": "bar"},
		"",
	},
	{
		"JSON Number",
		"",
		h256only.MapClaims{"foo": json.Number("123.4")},
		"",
	},
	{
		"Standard Claims",
		"",
		&h256only.StandardClaims{
			ExpiresAt: time.Now().Add(time.Second * 10).Unix(),
		},
		"",
	},
	{
		"Standard Expired Claims",
		"",
		&h256only.StandardClaims{
			ExpiresAt: time.Now().Add(-1 * time.Second * 10).Unix(),
		},
		"",
	},
}

func TestParser_Parse(t *testing.T) {

	// Iterate over test data set and run tests
	for _, data := range testData {
		// If the token string is blank, use helper function to generate string
		if data.tokenString == "" {
			data.tokenString = test.MakeSampleToken(data.claims, &hmacTestKey)
		}

		// Parse the token
		var token *h256only.Token
		var err error
		// Figure out correct claims type
		switch data.claims.(type) {
		case h256only.MapClaims:
			token, err = h256only.ParseWithClaims(data.tokenString, h256only.MapClaims{}, &hmacTestKey)
		case *h256only.StandardClaims:
			token, err = h256only.ParseWithClaims(data.tokenString, &h256only.StandardClaims{}, &hmacTestKey)
		default:
			panic("unknown type")
		}

		if data.err == "" {
			if err != nil {
				t.Errorf("[%v] Error while verifying token: %T:%v", data.name, err, err)
			}

			if (token == nil || token.Claims == nil) && data.claims != nil {
				t.Errorf("[%v]: nil token | token.Claims but data.claims was not nil: %v", data.name, data.claims)
				continue
			}
			// Verify result matches expectation
			if !reflect.DeepEqual(data.claims, token.Claims) {
				t.Errorf("[%v] Claims mismatch. Expecting: %#v Got: %#v", data.name, data.claims, token.Claims)
			}
			if token == nil || token.Signature == "" {
				t.Errorf("[%v] Signature is left unpopulated after parsing", data.name)
			}
		} else {
			if err == nil {
				t.Errorf("[%v] Expecting error.  Didn't get one.", data.name)
			} else {
				if err.Error() != data.err {
					t.Errorf("[%v]: err: got %q, want %q", data.name, err.Error(), data.err)
				}
			}
		}
	}
}

func BenchmarkHS256Signing(b *testing.B) {
	t := h256only.New()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := t.SignedString(&hmacTestKey); err != nil {
				b.Fatal(err)
			}
		}
	})
}
