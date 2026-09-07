//go:build !linux

package hostsecrets

import "context"

func Bootstrap(context.Context, Seed) error       { return ErrUnsupported }
func BootstrapFile(context.Context, string) error { return ErrUnsupported }

func AdmitServiceOwnershipFile(context.Context, string, string, string) error {
	return ErrUnsupported
}
