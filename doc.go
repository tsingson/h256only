// Package h256only implements a JWT-like parser with no configurability.
//
// The goal is to preserve the good part of JWT (a specification for sharing
// data with a signature in a web-safe way) while avoiding the bad parts (pretty
// much everything else). As a result, this library lacks many of the "features"
// commonly found in JWT libraries.
//
// See README.md for more info.
package h256only

const version = "4.0.0"
