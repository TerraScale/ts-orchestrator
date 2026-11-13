package app

import (
	"bytes"
	"errors"
)

type identityRekeyBoundedOutput struct {
	buffer    *bytes.Buffer
	remaining int
}

func (output *identityRekeyBoundedOutput) Write(wire []byte) (int, error) {
	if len(wire) > output.remaining {
		return 0, errors.New("identity rekey process observation exceeds its bound")
	}
	output.remaining -= len(wire)
	return output.buffer.Write(wire)
}
