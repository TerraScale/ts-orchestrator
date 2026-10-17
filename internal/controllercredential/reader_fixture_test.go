//go:build fixturetest

package controllercredential

import (
	"context"
	"errors"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/secrets"
)

func TestControllerReaderSDKFixtureRejectsUnadmittedInputs(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, input := range []struct {
		name   string
		ctx    context.Context
		client *secrets.SecretsClient
	}{
		{name: "missing SDK client", ctx: t.Context()},
		{name: "missing context", client: new(secrets.SecretsClient)},
		{name: "canceled context", ctx: canceled, client: new(secrets.SecretsClient)},
	} {
		t.Run(input.name, func(t *testing.T) {
			reader, err := OpenControllerReaderFromSDKFixture(input.ctx, input.client)
			if reader != nil || !errors.Is(err, ErrDelivery) {
				t.Fatalf("unadmitted input returned reader %v, error %v", reader, err)
			}
		})
	}
}
