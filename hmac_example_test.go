package h256only_test

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/kevinburke/h256only"
)

func ExampleNew_hmac() {
	// Load your secret key from a safe place and reuse it across multiple
	// calls. (Obviously don't use this example key for anything real.) If you
	// want to convert a passphrase to a key, use a suitable package like bcrypt
	// or scrypt.
	secretKeyBytes, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	if err != nil {
		panic(err)
	}

	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)

	// Create a new token object, specifying signing method and the claims
	// you would like it to contain.
	token := h256only.NewWithClaims(h256only.MapClaims{
		"foo": "bar",
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(&secretKey)

	fmt.Println(tokenString, err)
	// Output:
	// eyJ0eXAiOiJoMjU2b25seSJ9.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.qBIRJpbvtdNgqsSHjawY-x6sB7LL2416pb5r7LIVeUI <nil>
}

// Example parsing and validating a token using the HMAC signing method
func ExampleParse_hmac() {
	// sample token string taken from the New example
	tokenString := "eyJ0eXAiOiJoMjU2b25seSJ9.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.qBIRJpbvtdNgqsSHjawY-x6sB7LL2416pb5r7LIVeUI"

	// Load your secret key from a safe place and reuse it across multiple
	// calls. (Obviously don't use this example key for anything real.) If you
	// want to convert a passphrase to a key, use a suitable package like bcrypt
	// or scrypt.
	secretKeyBytes, err := hex.DecodeString("6368616e676520746869732070617373776f726420746f206120736563726574")
	if err != nil {
		panic(err)
	}

	var secretKey [32]byte
	copy(secretKey[:], secretKeyBytes)

	// Parse takes the token string and a key.
	token, err := h256only.Parse(tokenString, &secretKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	if claims, ok := token.Claims.(h256only.MapClaims); ok {
		fmt.Println(claims["foo"], claims["nbf"])
	}

	// Output: bar 1444478400
}
