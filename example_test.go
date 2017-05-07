package h256only_test

import (
	"encoding/hex"
	"fmt"

	"github.com/kevinburke/h256only"
)

// Example (atypical) using the StandardClaims type by itself to parse a token.
// The StandardClaims type is designed to be embedded into your custom types
// to provide standard validation features.  You can use it alone, but there's
// no way to retrieve other fields after parsing.
// See the CustomClaimsType example for intended usage.
func ExampleNewWithClaims_standardClaims() {
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

	// Create the Claims
	claims := &h256only.StandardClaims{
		ExpiresAt: 15000,
		Issuer:    "test",
	}

	token := h256only.NewWithClaims(claims)
	ss, err := token.SignedString(&secretKey)
	fmt.Printf("%v %v", ss, err)
	// Output:
	// eyJ0eXAiOiJoMjU2b25seSJ9.eyJleHAiOjE1MDAwLCJpc3MiOiJ0ZXN0In0.cO7MFTy0ZdHmDams4HwPMakWtBnnrjbQQtlBn37Ma4E <nil>
}

// Example creating a token using a custom claims type.  The StandardClaim is embedded
// in the custom type to allow for easy encoding, parsing and validation of standard claims.
func ExampleNewWithClaims_customClaimsType() {
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

	type MyCustomClaims struct {
		Foo string `json:"foo"`
		h256only.StandardClaims
	}

	// Create the Claims
	claims := MyCustomClaims{
		"bar",
		h256only.StandardClaims{
			ExpiresAt: 15000,
			Issuer:    "test",
		},
	}

	token := h256only.NewWithClaims(claims)
	ss, err := token.SignedString(&secretKey)
	fmt.Printf("%v %v", ss, err)
	//Output: eyJ0eXAiOiJoMjU2b25seSJ9.eyJmb28iOiJiYXIiLCJleHAiOjE1MDAwLCJpc3MiOiJ0ZXN0In0.ARUxT4aWsbVn9FUTSzl8-HVjC6qfmy3eRvhbNfaQflA <nil>
}

// Example creating a token using a custom claims type.  The StandardClaim is embedded
// in the custom type to allow for easy encoding, parsing and validation of standard claims.
func ExampleParseWithClaims_customClaimsType() {
	tokenString := "eyJ0eXAiOiJoMjU2b25seSJ9.eyJmb28iOiJiYXIiLCJleHAiOjE0MzA2OTQwMDAwMDAsImlzcyI6InRlc3QifQ.JimjTv_dcMV68Q5XyWA1z0ihqGHKFKAMhoaZjPkav04"
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

	type MyCustomClaims struct {
		Foo string `json:"foo"`
		h256only.StandardClaims
	}

	token, err := h256only.ParseWithClaims(tokenString, &MyCustomClaims{}, &secretKey)
	if err != nil {
		panic(err)
	}

	if claims, ok := token.Claims.(*MyCustomClaims); ok {
		fmt.Printf("%v %v", claims.Foo, claims.StandardClaims.ExpiresAt)
	}
	// Output: bar 1430694000000
}

// An example of parsing the error types using bitfield checks
func ExampleParse_errorChecking() {
	// Token from another example.  This token is expired
	var tokenString = "eyJ0eXAiOiJoMjU2b25seSJ9.eyJmb28iOiJiYXIiLCJleHAiOjE1MDAwLCJpc3MiOiJ0ZXN0In0.HE7fK0xOQwFEr4WDgRWj4teRPZ6i3GLwD5YCm6Pwu_c"
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

	token, err := h256only.Parse(tokenString, &secretKey)

	if token != nil {
		fmt.Println("Should have gotten an error; abort.")
	} else {
		fmt.Println(err.Error())
	}

	// Output: Token is expired
}
