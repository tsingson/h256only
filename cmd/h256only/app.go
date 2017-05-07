// A useful example app.  You can use this to debug your tokens on the command line.
// This is also a great place to look at how you might use this library.
//
// Example usage:
// The following will create and sign a token, then verify it and output the original claims.
//     echo {\"foo\":\"bar\"} | bin/h256only -key test/sample_key -alg RS256
//     -sign - | bin/h256only -key test/sample_key.pub -verify -
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/kevinburke/h256only"
)

var (
	// Options
	flagKey     = flag.String("key", "", "path to key file or '-' to read from stdin")
	flagCompact = flag.Bool("compact", false, "output compact JSON")
	flagDebug   = flag.Bool("debug", false, "print out all kinds of debug data")

	// Modes - exactly one of these is required
	flagSign   = flag.Bool("sign", false, "true to sign claims object - pass claims as JSON first argument")
	flagVerify = flag.Bool("verify", false, "true to verify a token - pass token as the first argument")
)

func main() {
	// Usage message if you ask for -help or if you mess up inputs.
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  One of the following flags is required: sign, verify\n")
		flag.PrintDefaults()
	}

	// Parse command line options
	flag.Parse()

	// Do the thing.  If something goes wrong, print error to stderr
	// and exit with a non-zero status code
	if err := start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// Figure out which thing to do and then do that
func start() error {
	if *flagSign {
		return signToken()
	} else if *flagVerify {
		return verifyToken()
	} else {
		flag.Usage()
		return fmt.Errorf("None of the required flags are present.  What do you want me to do?")
	}
}

// Helper func:  Read input from specified file or stdin
func loadData(p string) (*[32]byte, error) {
	if p == "" {
		return nil, fmt.Errorf("No path specified")
	}

	var rdr io.Reader
	if p == "-" {
		rdr = os.Stdin
	} else {
		if f, err := os.Open(p); err == nil {
			rdr = f
			defer f.Close()
		} else {
			return nil, err
		}
	}
	data, err := ioutil.ReadAll(rdr)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, errors.New("no data")
	}
	if data[len(data)-1] == '\n' {
		data = data[:len(data)-1]
	}
	var secretKey [32]byte
	switch len(data) {
	case 32:
		// assume it's the key
		copy(secretKey[:], data)
		return &secretKey, nil
	case 64:
		// assume the key is base64 encoded
		dst := make([]byte, hex.DecodedLen(len(data))) // should be 32
		_, err := hex.Decode(data, dst)
		if err != nil {
			return nil, err
		}

		copy(secretKey[:], dst)
		return &secretKey, nil
	default:
		return nil, errors.New("invalid key file, should have length 32 or 64")
	}
}

// Print a json object in accordance with the prophecy (or the command line options)
func printJSON(j interface{}) error {
	var out []byte
	var err error

	if *flagCompact {
		out, err = json.Marshal(j)
	} else {
		out, err = json.MarshalIndent(j, "", "    ")
	}

	if err == nil {
		fmt.Println(string(out))
	}

	return err
}

// Verify a token and output the claims.  This is a great example
// of how to verify and view a token.
func verifyToken() error {
	arg := flag.Arg(0)

	// trim possible whitespace from token
	if *flagDebug {
		fmt.Fprintf(os.Stderr, "Token len: %v bytes\n", len(arg))
	}

	key, err := loadData(*flagKey)
	if err != nil {
		return err
	}
	// Parse the token. Load the key from command line option
	token, err := h256only.Parse(arg, key)
	if err != nil {
		return err
	}

	// Print an error if we can't parse for some reason
	if err != nil {
		return fmt.Errorf("Couldn't parse token: %v", err)
	}

	// Print some debug data
	if *flagDebug && token != nil {
		fmt.Fprintf(os.Stderr, "Header:\n%v\n", token.Header)
		fmt.Fprintf(os.Stderr, "Claims:\n%v\n", token.Claims)
	}

	// Print the token details
	if err := printJSON(token.Claims); err != nil {
		return fmt.Errorf("Failed to output claims: %v", err)
	}

	return nil
}

// Create, sign, and output a token.  This is a great, simple example of
// how to use this library to create and sign a token.
func signToken() error {
	// get the token data from command line arguments
	arg := flag.Arg(0)
	if *flagDebug {
		fmt.Fprintf(os.Stderr, "Token: %v bytes", len(arg))
	}

	// parse the JSON of the claims
	var claims h256only.MapClaims
	if err := json.Unmarshal([]byte(arg), &claims); err != nil {
		return fmt.Errorf("Couldn't parse claims JSON: %v", err)
	}

	// get the key
	key, err := loadData(*flagKey)
	if err != nil {
		return fmt.Errorf("Couldn't read key: %v", err)
	}

	// create a new token
	token := h256only.NewWithClaims(claims)

	if out, err := token.SignedString(key); err == nil {
		fmt.Println(out)
	} else {
		return fmt.Errorf("Error signing token: %v", err)
	}

	return nil
}
