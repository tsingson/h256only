package h256only

import (
	"golang.org/x/xerrors"
)

// Error constants
var (
	ErrInvalidKey     = xerrors.New("key is invalid")
	ErrInvalidKeyType = xerrors.New("key is of invalid type")
)
