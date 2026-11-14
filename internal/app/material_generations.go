package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
)

// Material generation install (TS-668): the operator's requests to the
// authority leader. status needs a trusted signer; a change needs the
// signer's can_install_material grant, and a chain must be root-signed.

// exactSecretReader reads exact Vault versions with the instance principal of
// the cell cell returns, connecting on the first read.
func exactSecretReader(cell func() (oci.Region, error)) bootstrapstart.SecretReader {
	var vault *bootstrap.Vault
	return func(ctx context.Context, reference bootstrap.SecretReference) ([]byte, error) {
		if vault == nil {
			cell, err := cell()
			if err != nil {
				return nil, err
			}
			region, err := cell.OCIRegion()
			if err != nil {
				return nil, err
			}
			factory, err := ociclient.InstancePrincipal(region)
			if err != nil {
				return nil, err
			}
			if vault, err = bootstrap.NewInstancePrincipalVault(cell, factory.Provider()); err != nil {
				return nil, err
			}
		}
		return vault.ReadGenerationSecret(ctx, reference)
	}
}

// runRestoreControllerMaterial rebuilds the in-memory credential directory
// from Vault before bootstrap admission (TS-745).
func runRestoreControllerMaterial(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("restore-controller-material", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	remove := flags.Bool("remove-disk-copies", false, "delete the on-disk copies once each equals its Vault version")
	check := flags.Bool("check", false, "compare every installed file with its Vault version and change nothing")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || os.Geteuid() != 0 || *remove && *check {
		return errors.New("usage (root): restore-controller-material [--remove-disk-copies | --check]")
	}
	// The credential directory's tmpfs belongs to the host, where admission
	// and the controller see it.
	if moved, err := selfupdate.RunInHostMounts(ctx, output, os.Stderr); moved || err != nil {
		return err
	}
	note, err := bootstrapstart.RestoreMaterial(ctx, exactSecretReader(func() (oci.Region, error) {
		target, err := bootstrapstart.AcceptedGenerationTarget()
		return target.Expected.Cell, err
	}), *remove, *check)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(output, "restore-controller-material: "+note)
	return err
}
