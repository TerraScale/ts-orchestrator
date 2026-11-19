package releasefailure

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/nats-io/nats.go"
	"github.com/oracle/oci-go-sdk/v65/common"
)

type Failure struct {
	Stage string
	Code  string
	cause error
}

func (f *Failure) Error() string { return f.Stage + ": " + f.Code }
func (f *Failure) Unwrap() error { return f.cause }

func Policy(stage, code string) error { return &Failure{Stage: stage, Code: code} }

func At(stage string, err error) error {
	if err == nil {
		return nil
	}
	var failure *Failure
	if errors.As(err, &failure) {
		return failure
	}
	code := "unavailable"
	var registry *transport.Error
	var oracle common.ServiceError
	switch {
	case errors.Is(err, context.Canceled):
		code = "canceled"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, nats.ErrTimeout):
		code = "deadline exceeded"
	case errors.Is(err, nats.ErrNoResponders):
		code = "no responders"
	case errors.As(err, &registry):
		code = httpStatus(registry.StatusCode)
	case errors.As(err, &oracle):
		code = httpStatus(oracle.GetHTTPStatusCode())
	}
	return &Failure{Stage: stage, Code: code, cause: err}
}

func httpStatus(status int) string {
	if status < 400 || status > 599 {
		return "invalid HTTP response"
	}
	return fmt.Sprintf("HTTP %d", status)
}
