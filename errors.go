package h256only

import (
	"errors"
)

// Error constants
var (
	ErrInvalidKey     = errors.New("key is invalid")
	ErrInvalidKeyType = errors.New("key is of invalid type")
)
