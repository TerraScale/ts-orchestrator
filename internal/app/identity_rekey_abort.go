package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/nats-io/nats.go/jetstream"
)

// AbortIdentityRekey retires only the exact never-committed attempt while its
// original controller still serves. It archives proof and changes no material.
func AbortIdentityRekey(ctx context.Context, expectedSHA256 string, files map[string][]byte, js jetstream.JetStream) error {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return errors.New("identity rekey abort requires root:root")
	}
	layout := selfupdate.NewLayout(selfupdate.DefaultRoot)
	unlock, err := layout.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	journal, verified, err := bootstrapstart.ReadStagedIdentityRekeyEvidence(expectedSHA256)
	if err != nil {
		return err
	}
	accepted := verified.Accepted()
	config, err := validateIdentityRekeyFiles(accepted, files)
	if err != nil {
		return err
	}
	envelope, err := verified.ResetEnvelope()
	if err != nil {
		return err
	}
	uid, _, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	clock := controllerClockCheck(controllerBrokerClockProbe())
	observe := func(_ bootstrapstart.AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		if err := clock(); err != nil {
			return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, err
		}
		if _, pending, err := layout.Pending(); err != nil || pending {
			return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, errors.Join(selfupdate.ErrInvalid, err)
		}
		for _, path := range []string{filepath.Join(bootstrapstart.MaterialDirectory, ".generation-staging"),
			filepath.Join(controllerConfigDirectory, ".controller.json.generation"),
			filepath.Join(layout.Root, "restore-"+selfupdate.ControllerUnit+".json"),
			filepath.Join(layout.Root, "restore-"+selfupdate.HostUnit+".json"), filepath.Join(bootstrapstart.GenerationSpoolDirectory, bootstrapstart.GenerationArmedFile)} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, errors.Join(bootstrapstart.ErrMaterial, err)
			}
		}
		node, err := observeIdentityRekeyNodeBefore(ctx, uid, envelope.IssuedAt)
		if err != nil {
			return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, err
		}
		local, err := natscell.ObserveIdentityRekeyInstallation(config.NATS, node)
		if err != nil {
			return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, err
		}
		fresh, _, err := bootstrapstart.ReadStagedIdentityRekeyEvidence(expectedSHA256)
		if err != nil {
			return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, err
		}
		before, _ := protocol.EncodeJSON(journal)
		after, _ := protocol.EncodeJSON(fresh)
		if !bytes.Equal(before, after) {
			return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, bootstrapstart.ErrIdentityRekeyJournal
		}
		broker, store := controllerInstallationIdentity(local)
		return broker, store, nil
	}
	return bootstrapstart.NewMarkerStore().AbortIdentityRekeyJournal(ctx, expectedSHA256, js, observe)
}
