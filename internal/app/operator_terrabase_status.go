package app

import (
	"encoding/hex"
	"strings"
)

func lowerHexString(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil && strings.ToLower(value) == value
}
