//go:build fixturetest

package controllercredential

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/secrets"
)

// OpenControllerReaderFromSDKFixture uses the production protected snapshot,
// exact secret reader and authenticated connection with a temporary signed SDK
// client. It does not qualify instance-principal credentials or live OCI.
func OpenControllerReaderFromSDKFixture(ctx context.Context, client *secrets.SecretsClient) (*ControllerReader, error) {
	if client == nil {
		return nil, ErrDelivery
	}
	snapshot, err := controllerReaderConnectionSnapshot(ctx)
	if err != nil {
		return nil, err
	}
	reader, err := connectControllerReaderLease(ctx, snapshot, *client)
	if err != nil {
		return nil, err
	}
	if err := reader.Guard(ctx); err != nil {
		reader.conn.Close()
		return nil, err
	}
	return reader, nil
}
