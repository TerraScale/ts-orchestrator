package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	selfupdatecli "github.com/TerraScale/ts-orchestrator/internal/selfupdate/cli"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sys/unix"
)

var identityRekeyLaunchFiles = [...]string{bootstrapstart.HostEnrollmentFilename, bootstrapstart.OperatorSSHKeyFilename,
	bootstrapstart.ManagedHostImageReceiptFilename, bootstrapstart.ManagedHostImageDelegationFilename}

// StageIdentityRekey durably records reviewed authority while the old broker is
// still serving. It does not stop a service, alter releases, or mutate shared KV.
func StageIdentityRekey(ctx context.Context, journal bootstrapstart.IdentityRekeyJournal, stagedFiles map[string][]byte, generationChain []byte, js jetstream.JetStream) error {
	install, err := prepareIdentityRekey(ctx, journal, stagedFiles, generationChain, false, nil)
	if err != nil {
		return err
	}
	defer install.clearMaterial()
	unlock, err := selfupdate.NewLayout(selfupdate.DefaultRoot).Lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := install.check(ctx, false); err != nil {
		return err
	}
	if err := bootstrapstart.NewMarkerStore().PrepareIdentityRekeySuccessor(ctx, journal, js, time.Now().Round(0).UTC()); err != nil {
		return err
	}
	observe := func(_ bootstrapstart.AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		if err := install.check(ctx, false); err != nil {
			return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, err
		}
		broker, store := controllerInstallationIdentity(install.observation)
		return broker, store, nil
	}
	return bootstrapstart.NewMarkerStore().WriteIdentityRekeyJournal(install.journal, install.inputs, observe, time.Now().Round(0).UTC())
}

// StageAndPrecommitIdentityRekey samples and signs only after preparation and
// authentication. The exact durable journal is retained on every CAS outcome.
func StageAndPrecommitIdentityRekey(ctx context.Context, journal bootstrapstart.IdentityRekeyJournal, files map[string][]byte,
	chain []byte, js jetstream.JetStream, key ed25519.PrivateKey,
) (bootstrapstart.IdentityRekeyJournal, uint64, error) {
	install, err := prepareIdentityRekey(ctx, journal, files, chain, false, nil)
	if err != nil {
		return journal, 0, err
	}
	defer install.clearMaterial()
	unlock, err := selfupdate.NewLayout(selfupdate.DefaultRoot).Lock()
	if err != nil {
		return journal, 0, err
	}
	defer unlock()
	if err := install.check(ctx, false); err != nil {
		return journal, 0, err
	}
	if err := bootstrapstart.NewMarkerStore().PrepareIdentityRekeySuccessor(ctx, journal, js, time.Now().Round(0).UTC()); err != nil {
		return journal, 0, err
	}
	if present, err := bootstrapstart.IdentityRekeyJournalPresent(); err != nil || present {
		return journal, 0, errors.Join(bootstrapstart.ErrIdentityRekeyJournal, err)
	}
	if err := install.check(ctx, false); err != nil {
		return journal, 0, err
	}
	if err := authority.VerifyIdentityResetPredecessors(ctx, js, install.verified.Reset(), journal.Replicas); err != nil {
		return journal, 0, err
	}
	floor, err := authority.ObserveIdentityResetFloor(ctx, js, install.config.NATS.Cell, journal.Replicas)
	if err != nil {
		return journal, 0, err
	}
	journal, err = bootstrapstart.FinalizeIdentityRekeyJournal(install.verified, install.inputs, floor, key, time.Now().Round(0).UTC())
	if err != nil {
		return install.journal, 0, err
	}
	install.journal = journal
	install.accepted, err = bootstrapstart.DecodeAcceptedIdentity(journal.AcceptedWire)
	if err != nil {
		return journal, 0, err
	}
	observe := func(_ bootstrapstart.AcceptedIdentity) (identityrekey.BrokerIdentity, identityrekey.StoreIdentity, error) {
		if err := install.checkLocal(ctx, false); err != nil {
			return identityrekey.BrokerIdentity{}, identityrekey.StoreIdentity{}, err
		}
		broker, store := controllerInstallationIdentity(install.observation)
		return broker, store, nil
	}
	if err := bootstrapstart.NewMarkerStore().WriteIdentityRekeyJournal(journal, install.inputs, observe, time.Now().Round(0).UTC()); err != nil {
		return journal, 0, err
	}
	if err := install.checkLocal(ctx, false); err != nil {
		return journal, 0, err
	}
	envelope, err := install.verified.ResetEnvelope()
	if err != nil {
		return journal, 0, err
	}
	sequence, err := authority.ResetIdentityLease(ctx, js, envelope, install.verified.InstallationRoots(install.inputs), install.verified.ResetTarget(), time.Now().Round(0).UTC())
	return journal, sequence, err
}

// InstallIdentityRekey installs only an already staged and shared-committed
// target on a stopped controller. Accepted publication is the local commit.
func InstallIdentityRekey(ctx context.Context, journal bootstrapstart.IdentityRekeyJournal, stagedFiles map[string][]byte, generationChain []byte, js jetstream.JetStream) error {
	install, err := prepareIdentityRekey(ctx, journal, stagedFiles, generationChain, true, js)
	if err != nil {
		return err
	}
	defer install.clearMaterial()
	if err := install.check(ctx, true); err != nil {
		return err
	}
	unlock, err := selfupdate.NewLayout(selfupdate.DefaultRoot).Lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := install.check(ctx, true); err != nil {
		return err
	}
	if err := natscell.PinIdentityRekeyInstallation(install.config.NATS, install.observation, install.serviceUID, install.serviceGID); err != nil {
		return err
	}
	install.pinned = true
	// The pending copy is required by native generation recovery before any
	// material rename; it contains the exact config pinned by this acceptance.
	if err := install.write(ctx, controllerConfigDirectory, ".controller.json.generation", install.files[controllerConfigFilename]); err != nil {
		return err
	}
	if err := install.check(ctx, true); err != nil {
		return err
	}
	if err := install.material.VerifyIdentityRekeyMaterialAdoption(install.target, install.verified.InstallationRoots(install.inputs), install.chain, install.verified.InstallationTime(time.Now().Round(0).UTC())); err != nil {
		return err
	}
	if err := install.material.FinishIdentityRekeyMaterialAdoption(install.verified, install.inputs,
		controllerSidecarPath(controllerConfigFilename), install.verified.InstallationTime(time.Now().Round(0).UTC())); err != nil {
		return err
	}
	if err := install.check(ctx, true); err != nil {
		return err
	}
	if err := install.material.AdoptIdentityRekeyGeneration(install.verified, install.inputs,
		install.generationFiles, install.files[controllerConfigFilename], install.verified.InstallationTime(time.Now().Round(0).UTC())); err != nil {
		return err
	}
	if err := install.material.InstallIdentityRekeyResponseKey(ctx, install.verified, install.inputs,
		install.contents[install.accepted.Slot+"-response.key"], func(ctx context.Context) error { return install.check(ctx, true) }, time.Now().Round(0).UTC()); err != nil {
		return err
	}
	for _, name := range bootstrap.ControllerConfigFileNames {
		if err := install.write(ctx, controllerConfigDirectory, name, install.files[name]); err != nil {
			return err
		}
	}
	for _, name := range install.launchFiles {
		if err := install.write(ctx, bootstrapstart.BakedDirectory, name, install.files[name]); err != nil {
			return err
		}
	}
	if err := install.write(ctx, controllerConfigDirectory, controllerConfigFilename, install.files[controllerConfigFilename]); err != nil {
		return err
	}
	if err := install.verifyInstalledMaterial(ctx); err != nil {
		return err
	}
	if err := install.check(ctx, true); err != nil {
		return err
	}
	if err := bootstrapstart.NewMarkerStore().ReplaceIdentity(install.verified.Checkpoint(), install.accepted.Slot,
		install.accepted.AcceptedAt, controllerIdentityObserver(install.config)); err != nil {
		return err
	}
	return bootstrapstart.CheckIdentityRekeyPrestart(install.accepted)
}

type identityRekeyInstall struct {
	journal         bootstrapstart.IdentityRekeyJournal
	accepted        bootstrapstart.AcceptedIdentity
	verified        bootstrapstart.VerifiedIdentityRekey
	inputs          bootstrapstart.TrustInputs
	config          Config
	files           map[string][]byte
	launchFiles     []string
	chain           []byte
	material        bootstrapstart.MaterialStore
	target          bootstrapstart.GenerationTarget
	generationFiles map[string][]byte
	contents        map[string][]byte
	imds            bootstrapstart.IMDSClient
	instances       *bootstrapstart.OCIInstanceObserver
	serviceUID      uint32
	serviceGID      uint32
	pinned          bool
	observation     natscell.InstallationIdentity
	clock           func() error
	js              jetstream.JetStream
	store           os.FileInfo
}

func prepareIdentityRekey(ctx context.Context, journal bootstrapstart.IdentityRekeyJournal, stagedFiles map[string][]byte,
	generationChain []byte, stopped bool, js jetstream.JetStream,
) (*identityRekeyInstall, error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return nil, errors.New("identity rekey installation requires root:root")
	}
	wire, err := protocol.EncodeJSON(journal)
	if err != nil {
		return nil, err
	}
	var frozen bootstrapstart.IdentityRekeyJournal
	if err := protocol.DecodeStrict(wire, &frozen, bootstrapstart.MaxIdentityRekeyJournalBytes); err != nil {
		return nil, err
	}
	install := &identityRekeyInstall{journal: frozen, chain: bytes.Clone(generationChain), files: maps.Clone(stagedFiles),
		imds: bootstrapstart.NewIMDSClient(), clock: controllerClockCheck(controllerBrokerClockProbe()), js: js}
	for name, content := range install.files {
		install.files[name] = bytes.Clone(content)
	}
	if err := install.clock(); err != nil {
		return nil, err
	}
	verify := bootstrapstart.VerifyIdentityRekeyInstall
	if stopped {
		verify = func(journal bootstrapstart.IdentityRekeyJournal, now time.Time) (bootstrapstart.VerifiedIdentityRekey, bootstrapstart.TrustInputs, error) {
			return bootstrapstart.VerifyCommittedIdentityRekeyInstall(ctx, journal, install.js, now)
		}
	}
	install.verified, install.inputs, err = verify(install.journal, time.Now().Round(0).UTC())
	if err != nil {
		return nil, err
	}
	install.accepted = install.verified.Accepted()
	install.launchFiles, err = bootstrapstart.AcceptedLaunchFileNames(install.accepted)
	if err != nil {
		return nil, err
	}
	install.config, err = validateIdentityRekeyFiles(install.accepted, install.files)
	if err != nil {
		return nil, err
	}
	if err := verifyIdentityRekeyGlobalScope(install.config, install.verified.Reset()); err != nil {
		return nil, err
	}
	launch := map[string][]byte{}
	for _, name := range install.launchFiles {
		launch[name] = install.files[name]
	}
	if err := install.verified.VerifyLaunchMaterialContext(ctx, install.inputs, install.files["oci-region.json"], launch, time.Now().Round(0).UTC()); err != nil {
		return nil, err
	}
	if err := verifyIdentityRekeyResponseBundle(install.journal, launch[bootstrapstart.HostEnrollmentFilename]); err != nil {
		return nil, err
	}
	install.target, err = bootstrapstart.GenerationTargetFromAccepted(install.accepted)
	if err != nil {
		return nil, err
	}
	if len(install.chain) == 0 || len(install.journal.Values) < 3 || !bytes.Equal(install.chain, install.journal.Values[2]) {
		return nil, errors.New("identity rekey generation chain differs from the signed shared reset")
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(install.chain)
	if err != nil {
		return nil, err
	}
	generations, err := install.target.VerifyChain(chain, install.verified.InstallationRoots(install.inputs), install.verified.InstallationTime(time.Now().Round(0).UTC()))
	if err != nil {
		return nil, err
	}
	newest := generations[len(generations)-1]
	if newest.Fingerprint() != install.accepted.MaterialGenerationSHA256 {
		return nil, errors.New("identity rekey must install exactly its signed material generation")
	}
	serviceUID, serviceGID, err := controllerServiceIdentity()
	if err != nil {
		return nil, err
	}
	install.serviceUID = serviceUID
	install.serviceGID = serviceGID
	install.material, err = bootstrapstart.NewMaterialStore(nil, serviceUID, serviceGID)
	if err != nil {
		return nil, err
	}
	install.store, err = os.Stat(install.accepted.Store.Directory)
	if err != nil || !install.store.IsDir() {
		return nil, errors.New("identity rekey requires the existing physical store")
	}
	provider, err := bootstrap.NewRegionalInstancePrincipalConfigurationProvider(oci.Region(install.accepted.Cell))
	if err != nil {
		return nil, err
	}
	install.instances, err = bootstrapstart.NewOCIInstanceObserver(oci.Region(install.accepted.Cell), provider)
	if err != nil {
		return nil, err
	}
	vault, err := bootstrap.NewInstancePrincipalVault(oci.Region(install.accepted.Cell), provider)
	if err != nil {
		return nil, err
	}
	if err := install.check(ctx, stopped); err != nil {
		return nil, err
	}
	read := func(ctx context.Context, reference bootstrap.SecretReference) ([]byte, error) {
		if err := install.check(ctx, stopped); err != nil {
			return nil, err
		}
		return vault.ReadGenerationSecret(ctx, reference)
	}
	install.contents, err = install.material.ReadIdentityRekeyMaterial(ctx, install.accepted, install.chain,
		install.verified.InstallationRoots(install.inputs), read, install.verified.InstallationTime(time.Now().Round(0).UTC()))
	if err != nil {
		return nil, err
	}
	if err := verifyIdentityRekeyResponseKey(install.journal, install.accepted, install.files[bootstrapstart.HostEnrollmentFilename], install.contents[install.accepted.Slot+"-response.key"]); err != nil {
		install.clearMaterial()
		return nil, err
	}
	if err := install.material.VerifyIdentityRekeyResponseKey(ctx, install.verified, install.inputs,
		install.contents[install.accepted.Slot+"-response.key"], time.Now().Round(0).UTC()); err != nil {
		install.clearMaterial()
		return nil, err
	}
	checked := maps.Clone(install.contents)
	checked[bootstrapstart.GenerationConfigFile(install.accepted.Slot)] = install.files[controllerConfigFilename]
	if err := install.target.VerifyFiles(newest.Generation(), func(name string) ([]byte, error) {
		if content, exists := checked[name]; exists {
			return content, nil
		}
		return nil, os.ErrNotExist
	}, install.verified.InstallationTime(time.Now().Round(0).UTC())); err != nil {
		install.clearMaterial()
		return nil, err
	}
	install.generationFiles = map[string][]byte{}
	for _, reference := range newest.Generation().Secrets {
		if reference.Slot == "" || reference.Slot == install.accepted.Slot {
			install.generationFiles[reference.TargetFile] = install.contents[reference.TargetFile]
		}
	}
	if err := install.material.VerifyIdentityRekeyMaterialAdoption(install.target, install.verified.InstallationRoots(install.inputs), install.chain, install.verified.InstallationTime(time.Now().Round(0).UTC())); err != nil {
		install.clearMaterial()
		return nil, err
	}
	return install, nil
}

func validateIdentityRekeyFiles(accepted bootstrapstart.AcceptedIdentity, files map[string][]byte) (Config, error) {
	if err := accepted.Validate(); err != nil {
		return Config{}, err
	}
	launchFiles, err := bootstrapstart.AcceptedLaunchFileNames(accepted)
	if err != nil {
		return Config{}, err
	}
	if len(files) != 4+len(launchFiles) || len(accepted.LaunchMaterialSHA256) != len(launchFiles) {
		return Config{}, errors.New("identity rekey requires the exact accepted config and launch file set")
	}
	for name, want := range accepted.ConfigSHA256 {
		if len(files[name]) == 0 || controllerSHA256(files[name]) != want {
			return Config{}, fmt.Errorf("identity rekey config %s differs from its accepted pin", name)
		}
	}
	for _, name := range launchFiles {
		if len(files[name]) == 0 || controllerSHA256(files[name]) != accepted.LaunchMaterialSHA256[name] {
			return Config{}, fmt.Errorf("identity rekey launch material %s differs from its accepted pin", name)
		}
	}
	sidecars := make([]bootstrap.ControllerConfigFile, 0, len(bootstrap.ControllerConfigFileNames))
	for _, name := range bootstrap.ControllerConfigFileNames {
		sidecars = append(sidecars, bootstrap.ControllerConfigFile{Name: name, Bytes: files[name], SHA256: accepted.ConfigSHA256[name]})
	}
	config, err := ValidateAcceptedControllerConfig(accepted, files[controllerConfigFilename], accepted.ConfigSHA256[controllerConfigFilename], sidecars)
	if err != nil {
		return Config{}, err
	}
	if config.Controller.SelfUpdateRoot != "" && config.Controller.SelfUpdateRoot != selfupdate.DefaultRoot {
		return Config{}, errors.New("identity rekey requires the fixed production release layout")
	}
	region, err := oci.ParseRegionConfig(files["oci-region.json"])
	if err != nil {
		return Config{}, err
	}
	if region.Region != oci.Region(accepted.Cell) {
		return Config{}, errors.New("identity rekey launch image belongs to another cell")
	}
	return config, nil
}

func (install *identityRekeyInstall) check(ctx context.Context, stopped bool) error {
	if err := install.checkLocal(ctx, stopped); err != nil {
		return err
	}
	descriptor, err := install.imds.FetchDescriptor(ctx)
	if err != nil {
		return err
	}
	instance, err := install.imds.FetchInstanceID(ctx)
	if err != nil {
		return err
	}
	if descriptor.SchemaVersion != 1 || descriptor.Slot != install.accepted.Slot || instance != install.accepted.InstanceOCID {
		return errors.New("identity rekey local IMDS differs from the signed target")
	}
	observed, err := install.instances.ObserveInstance(ctx, instance)
	if err != nil {
		return err
	}
	if observed.InstanceOCID != install.accepted.InstanceOCID || observed.ImageOCID != install.accepted.ImageOCID ||
		observed.PrimaryVNICOCID != install.accepted.PrimaryVNICOCID || observed.PrimaryPrivateIP != install.accepted.PrimaryPrivateIP ||
		!observed.PrimaryVNIC || observed.LifecycleState != "RUNNING" {
		return errors.New("identity rekey authenticated OCI facts differ from the signed target")
	}
	return install.checkLocal(ctx, stopped)
}

func (install *identityRekeyInstall) checkLocal(ctx context.Context, stopped bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := install.clock(); err != nil {
		return err
	}
	verify := bootstrapstart.VerifyIdentityRekeyInstall
	if stopped {
		verify = func(journal bootstrapstart.IdentityRekeyJournal, now time.Time) (bootstrapstart.VerifiedIdentityRekey, bootstrapstart.TrustInputs, error) {
			return bootstrapstart.VerifyCommittedIdentityRekeyInstall(ctx, journal, install.js, now)
		}
	}
	verified, inputs, err := verify(install.journal, time.Now().Round(0).UTC())
	if err != nil {
		return err
	}
	if stopped {
		if err := verifyIdentityRekeyControllerStopped(ctx, install.serviceUID); err != nil {
			return err
		}
		if err := selfupdatecli.VerifyIdentityRekeyBinaries(ctx, install.accepted, inputs); err != nil {
			return err
		}
	}
	if _, err := bootstrapstart.VerifyAcceptedRunningBinary(install.accepted.Binary); err != nil {
		return err
	}
	var local natscell.InstallationIdentity
	if install.pinned {
		if err := bootstrapstart.VerifyAcceptedLocalIdentity(install.accepted, controllerIdentityObserver(install.config)); err != nil {
			return err
		}
		local, err = natscell.ObserveInstalledIdentity(install.config.NATS)
	} else {
		node := install.accepted.Store.RaftNodeID
		if !stopped {
			node, err = observeIdentityRekeyActiveNode(ctx, install.serviceUID)
			if err != nil {
				return err
			}
		}
		local, err = natscell.ObserveIdentityRekeyInstallation(install.config.NATS, node)
	}
	if err != nil {
		return err
	}
	broker, store := controllerInstallationIdentity(local)
	if broker != install.accepted.Broker || store != install.accepted.Store {
		return errors.New("identity rekey actual broker/store differs from its root checkpoint")
	}
	current, err := os.Stat(install.accepted.Store.Directory)
	if err != nil || !os.SameFile(install.store, current) {
		return errors.New("identity rekey physical store changed during installation")
	}
	if err := install.clock(); err != nil {
		return err
	}
	if stopped {
		if err := verifyIdentityRekeyControllerStopped(ctx, install.serviceUID); err != nil {
			return err
		}
	}
	// Network observations cannot preserve expired authority or a replaced
	// predecessor; reload the fixed journal and roots at the effect boundary.
	verified, inputs, err = verify(install.journal, time.Now().Round(0).UTC())
	if err != nil {
		return err
	}
	now := verified.InstallationTime(time.Now().Round(0).UTC())
	chain, err := bootstrap.DecodeMaterialGenerationChain(install.chain)
	if err != nil {
		return err
	}
	generations, err := install.target.VerifyChain(chain, verified.InstallationRoots(inputs), now)
	if err != nil {
		return err
	}
	newest := generations[len(generations)-1]
	if newest.Fingerprint() != install.accepted.MaterialGenerationSHA256 {
		return bootstrapstart.ErrMaterial
	}
	if install.contents != nil {
		if err := install.target.VerifyFiles(newest.Generation(), func(name string) ([]byte, error) {
			if name == bootstrapstart.GenerationConfigFile(install.accepted.Slot) {
				return install.files[controllerConfigFilename], nil
			}
			if wire, exists := install.contents[name]; exists {
				return wire, nil
			}
			return nil, os.ErrNotExist
		}, now); err != nil {
			return err
		}
	}
	launch := map[string][]byte{}
	for _, name := range install.launchFiles {
		launch[name] = install.files[name]
	}
	if err := verified.VerifyLaunchMaterialContext(ctx, inputs, install.files["oci-region.json"], launch, time.Now().Round(0).UTC()); err != nil {
		return err
	}
	if err := install.material.VerifyIdentityRekeyMaterialPredecessors(verified, inputs, now); err != nil {
		return err
	}
	install.verified, install.inputs, install.observation = verified, inputs, local
	return ctx.Err()
}

func (install *identityRekeyInstall) write(ctx context.Context, directory, name string, wire []byte) error {
	if err := install.check(ctx, true); err != nil {
		return err
	}
	dir, err := openControllerConfigDirectory(directory)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	return replaceIdentityRekeyFile(dir, name, wire, 0, 0)
}

func (install *identityRekeyInstall) clearMaterial() {
	for _, wire := range install.contents {
		clear(wire)
	}
}

func (install *identityRekeyInstall) verifyInstalledMaterial(ctx context.Context) error {
	for name, want := range install.files {
		directory := controllerConfigDirectory
		if slices.Contains(install.launchFiles, name) {
			directory = bootstrapstart.BakedDirectory
		}
		wire, err := readInstalledControllerFile(directory, name, 0, 0, 0o444, len(want))
		if err != nil || !bytes.Equal(wire, want) {
			return fmt.Errorf("identity rekey installed public file %s differs from its target: %w", name, errors.Join(err, bootstrapstart.ErrLaunchMaterial))
		}
	}
	pins, err := install.material.VerifyIdentityRekeyInstalledMaterial(ctx, install.accepted, install.verified.InstallationRoots(install.inputs),
		install.chain, install.files[controllerConfigFilename], install.verified.InstallationTime(time.Now().Round(0).UTC()))
	if err != nil {
		return err
	}
	checker, err := bootstrapstart.NewLiveCredentialChecker(install.config.NATS, install.serviceUID, install.serviceGID,
		install.config.Controller.ResponseKeyFile, install.config.Controller.BrokerTicketKeyFile, install.config.Controller.HostNATSIssuerSeedFile,
		install.config.Controller.HostTLSIssuerKeyFile, install.config.Controller.HostTLSIssuerCertFile, func() error {
			if _, err := readPrivateKey(install.config.Controller.ResponseKeyFile); err != nil {
				return err
			}
			_, _, err := brokerTicketKeys(install.config)
			return err
		})
	if err != nil {
		return err
	}
	checker.ControllerConfig = install.files[controllerConfigFilename]
	checker.TerraBaseCACertFile, checker.TerraBaseCAKeyFile = install.config.Controller.TerraBaseCACertFile, install.config.Controller.TerraBaseCAKeyFile
	return checker.VerifyLiveCredentials(ctx, pins, install.accepted)
}

// replaceIdentityRekeyFile only writes signed public files in already held
// root directories. Existing identity authority is never parsed.
func replaceIdentityRekeyFile(dir int, name string, wire []byte, uid, gid uint32) error {
	if len(wire) == 0 || len(wire) > bootstrap.MaxControllerConfigBytes || filepath.Base(name) != name || name == "." || name == ".." {
		return errors.New("invalid identity rekey file")
	}
	var existing unix.Stat_t
	if err := unix.Fstatat(dir, name, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if existing.Mode&unix.S_IFMT != unix.S_IFREG || existing.Nlink != 1 || existing.Uid != uid || existing.Mode&0o002 != 0 {
			return errors.New("identity rekey destination is not an owned regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary := ".identity-rekey." + rand.Text()
	fd, err := unix.Openat(dir, temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o444)
	if err != nil {
		return err
	}
	defer unix.Unlinkat(dir, temporary, 0)
	file := os.NewFile(uintptr(fd), temporary)
	defer file.Close()
	if err := file.Chown(int(uid), int(gid)); err != nil {
		return err
	}
	if err := file.Chmod(0o444); err != nil {
		return err
	}
	if n, err := file.Write(wire); err != nil || n != len(wire) {
		return errors.Join(err, io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(dir, temporary, dir, name); err != nil {
		return err
	}
	return unix.Fsync(dir)
}

func verifyIdentityRekeyControllerStopped(ctx context.Context, serviceUID uint32) error {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(probeCtx, "/usr/bin/systemctl", "show", selfupdate.ControllerUnit,
		"--property=LoadState,ActiveState,SubState,MainPID,ControlPID,KillMode")
	command.WaitDelay = time.Second
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("inspect stopped controller service: %w", err)
	}
	if err := validateIdentityRekeyStoppedState(output); err != nil {
		return err
	}
	return verifyIdentityRekeyNoServiceProcesses("/proc", serviceUID)
}

func validateIdentityRekeyStoppedState(wire []byte) error {
	fields := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(wire)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || fields[key] != "" {
			return errors.New("invalid controller service observation")
		}
		fields[key] = value
	}
	if fields["LoadState"] != "loaded" || fields["ActiveState"] != "inactive" || fields["SubState"] != "dead" ||
		fields["MainPID"] != "0" || fields["ControlPID"] != "0" || fields["KillMode"] != "control-group" {
		return errors.New("identity rekey requires an inactive/dead controller with no main or control process")
	}
	return nil
}

func verifyIdentityRekeyNoServiceProcesses(directory string, serviceUID uint32) error {
	if serviceUID == 0 {
		return errors.New("identity rekey requires a dedicated non-root controller service UID")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
			continue
		}
		wire, err := os.ReadFile(filepath.Join(directory, entry.Name(), "status"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		found := false
		for line := range strings.SplitSeq(string(wire), "\n") {
			if !strings.HasPrefix(line, "Uid:") {
				continue
			}
			values := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(values) != 4 {
				return errors.New("invalid local process UID observation")
			}
			for _, value := range values {
				uid, err := strconv.ParseUint(value, 10, 32)
				if err != nil {
					return err
				}
				if uint32(uid) == serviceUID {
					return errors.New("identity rekey refused a remaining controller service process")
				}
			}
			found = true
		}
		if !found {
			return errors.New("local process UID observation is missing")
		}
	}
	return nil
}

type identityRekeyActiveService struct {
	PID        uint32
	Invocation string
}

func identityRekeyActiveServiceState(wire []byte) (identityRekeyActiveService, error) {
	fields := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(wire)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || fields[key] != "" {
			return identityRekeyActiveService{}, errors.New("invalid active controller service observation")
		}
		fields[key] = value
	}
	pid, err := strconv.ParseUint(fields["MainPID"], 10, 32)
	invocation := fields["InvocationID"]
	if err != nil || pid == 0 || len(invocation) != 32 || fields["LoadState"] != "loaded" || fields["ActiveState"] != "active" ||
		fields["SubState"] != "running" || fields["ControlPID"] != "0" {
		return identityRekeyActiveService{}, errors.New("identity rekey staging requires an independently observed active controller")
	}
	for _, char := range invocation {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return identityRekeyActiveService{}, errors.New("invalid controller invocation ID")
		}
	}
	return identityRekeyActiveService{PID: uint32(pid), Invocation: invocation}, nil
}

// observeIdentityRekeyActiveNode uses journald's trusted process/invocation
// metadata, never a configured name or a newly constructed NATS server.
func observeIdentityRekeyActiveNode(ctx context.Context, serviceUID uint32) (string, error) {
	return observeIdentityRekeyNodeBefore(ctx, serviceUID, time.Now().Round(0).UTC())
}

func observeIdentityRekeyNodeBefore(ctx context.Context, serviceUID uint32, startedBefore time.Time) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	readService := func() (identityRekeyActiveService, error) {
		command := exec.CommandContext(probeCtx, "/usr/bin/systemctl", "show", selfupdate.ControllerUnit,
			"--property=LoadState,ActiveState,SubState,MainPID,ControlPID,InvocationID")
		command.WaitDelay = time.Second
		wire, err := command.Output()
		if err != nil {
			return identityRekeyActiveService{}, err
		}
		return identityRekeyActiveServiceState(wire)
	}
	before, err := readService()
	if err != nil {
		return "", err
	}
	if err := verifyIdentityRekeyActiveProcess(before.PID, serviceUID); err != nil {
		return "", err
	}
	pid := strconv.FormatUint(uint64(before.PID), 10)
	command := exec.CommandContext(probeCtx, "/usr/bin/journalctl", "--no-pager", "--output=json", "--lines=8",
		"--output-fields=_PID,_SYSTEMD_INVOCATION_ID,_SYSTEMD_UNIT,MESSAGE,__REALTIME_TIMESTAMP", "_PID="+pid,
		"_SYSTEMD_INVOCATION_ID="+before.Invocation, "_SYSTEMD_UNIT="+selfupdate.ControllerUnit,
		"--grep=^\\["+pid+"\\] \\[INF\\][[:space:]]+Node:[[:space:]]+[A-Za-z0-9]+$")
	command.WaitDelay = time.Second
	var output bytes.Buffer
	command.Stdout = &identityRekeyBoundedOutput{buffer: &output, remaining: 32 << 10}
	if err := command.Run(); err != nil {
		return "", err
	}
	node, err := identityRekeyJournalNodeBefore(output.Bytes(), before, startedBefore)
	if err != nil {
		return "", err
	}
	after, err := readService()
	if err != nil || after != before {
		return "", errors.New("controller process changed during live Raft identity observation")
	}
	if err := verifyIdentityRekeyActiveProcess(after.PID, serviceUID); err != nil {
		return "", err
	}
	return node, nil
}

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

func verifyIdentityRekeyActiveProcess(pid, serviceUID uint32) error {
	if pid == 0 || serviceUID == 0 {
		return errors.New("invalid controller process observation")
	}
	path := filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10))
	process, err := os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := process.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != serviceUID {
		return errors.New("controller process is not owned by its dedicated service UID")
	}
	executable, err := os.Stat(filepath.Join(path, "exe"))
	if err != nil {
		return err
	}
	stat, ok = executable.Sys().(*syscall.Stat_t)
	if !ok || !executable.Mode().IsRegular() || executable.Size() <= 0 || stat.Uid != 0 || stat.Gid != 0 || executable.Mode().Perm()&0o022 != 0 {
		return errors.New("active controller executable is not immutable root-owned material")
	}
	return nil
}

func identityRekeyJournalNode(wire []byte, service identityRekeyActiveService) (string, error) {
	return identityRekeyJournalNodeBefore(wire, service, time.Now().Round(0).UTC())
}

func identityRekeyJournalNodeBefore(wire []byte, service identityRekeyActiveService, startedBefore time.Time) (string, error) {
	if len(wire) == 0 || len(wire) > 32<<10 {
		return "", errors.New("live Raft node journal observation is absent or oversized")
	}
	pid := strconv.FormatUint(uint64(service.PID), 10)
	node := ""
	for line := range bytes.SplitSeq(bytes.TrimSpace(wire), []byte("\n")) {
		var row map[string]string
		if err := json.Unmarshal(line, &row); err != nil {
			return "", err
		}
		if row["_PID"] != pid || row["_SYSTEMD_INVOCATION_ID"] != service.Invocation || row["_SYSTEMD_UNIT"] != selfupdate.ControllerUnit {
			return "", errors.New("Raft node record is not from the observed controller invocation")
		}
		micros, err := strconv.ParseInt(row["__REALTIME_TIMESTAMP"], 10, 64)
		if err != nil || micros <= 0 || startedBefore.IsZero() || !time.UnixMicro(micros).Before(startedBefore) {
			return "", errors.New("controller invocation does not predate this identity reset")
		}
		fields := strings.Fields(row["MESSAGE"])
		if len(fields) != 4 || fields[0] != "["+pid+"]" || fields[1] != "[INF]" || fields[2] != "Node:" || len(fields[3]) != 8 {
			return "", errors.New("Raft node record is not an exact NATS startup observation")
		}
		for _, char := range fields[3] {
			if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9') {
				return "", errors.New("invalid advertised Raft node identity")
			}
		}
		if node != "" && node != fields[3] {
			return "", errors.New("controller invocation advertised conflicting Raft node identities")
		}
		node = fields[3]
	}
	return node, nil
}

// CleanupIdentityRekey deletes only named obsolete authority inputs after
// immutable shared completion. Current genesis, chains, launch pins and data stay.
func CleanupIdentityRekey(ctx context.Context) error {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return errors.New("identity rekey cleanup requires root:root")
	}
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return err
	}
	journal, err := bootstrapstart.ReadIdentityRekeyJournal(accepted)
	if err != nil {
		return err
	}
	journalWire := journal.Wire()
	uid, gid, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	check := func() error {
		if err := controllerClockCheck(controllerBrokerClockProbe())(); err != nil {
			return err
		}
		inputs, err := bootstrapstart.LoadTrustInputs(accepted)
		if err != nil {
			return err
		}
		if err := bootstrapstart.CheckIdentityRekeyPrestart(accepted); err != nil {
			return err
		}
		if err := selfupdatecli.VerifyIdentityRekeyBinaries(ctx, accepted, inputs); err != nil {
			return err
		}
		current, err := selfupdate.NewLayout(selfupdate.DefaultRoot).Current()
		if err != nil || current == "" {
			return errors.New("identity rekey cleanup has no compatible current release")
		}
		probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		command := exec.CommandContext(probeCtx, selfupdate.NewLayout(selfupdate.DefaultRoot).BinaryPath(current),
			"identity-rekey-completion-check", "--config", controllerSidecarPath(controllerConfigFilename))
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid}}
		command.WaitDelay = time.Second
		if err := command.Run(); err != nil {
			return fmt.Errorf("identity rekey cleanup shared completion: %w", err)
		}
		fresh, err := bootstrapstart.ReadIdentityRekeyJournal(accepted)
		if err != nil {
			return err
		}
		if !bytes.Equal(fresh.Wire(), journalWire) {
			return bootstrapstart.ErrIdentityRekeyJournal
		}
		inputs, err = bootstrapstart.LoadTrustInputs(accepted)
		if err != nil {
			return err
		}
		if err := controllerClockCheck(controllerBrokerClockProbe())(); err != nil {
			return err
		}
		if err := bootstrapstart.CheckIdentityRekeyPrestart(accepted); err != nil {
			return err
		}
		return ctx.Err()
	}
	if err := check(); err != nil {
		return err
	}
	for _, group := range []struct {
		directory string
		names     []string
		uid, gid  uint32
	}{
		{bootstrapstart.BakedDirectory, []string{"identity.json", "anchor.json"}, 0, 0},
		{controllerConfigDirectory, []string{controllerManifestFilename}, 0, 0},
		{bootstrapstart.MarkerDirectory, []string{"initial-formation.json"}, 0, 0},
	} {
		dir, err := openControllerConfigDirectory(group.directory)
		if err != nil {
			return err
		}
		for _, name := range group.names {
			if err := unlinkRetiredIdentityInput(dir, name, group.uid, group.gid, check); err != nil {
				unix.Close(dir)
				return err
			}
		}
		unix.Close(dir)
	}
	return nil
}

func unlinkRetiredIdentityInput(dir int, name string, uid, gid uint32, check func() error) error {
	if !slices.Contains([]string{"identity.json", "anchor.json", controllerManifestFilename, "initial-formation.json"}, name) {
		return errors.New("identity rekey cleanup refuses an unrelated name")
	}
	if check == nil {
		return errors.New("identity rekey cleanup requires verified shared completion")
	}
	if err := check(); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(dir, name, &stat, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uid || stat.Gid != gid || stat.Nlink != 1 || stat.Mode&0o022 != 0 {
		return errors.New("identity rekey cleanup refuses indirect or unowned authority input")
	}
	if err := unix.Unlinkat(dir, name, 0); err != nil {
		return err
	}
	return unix.Fsync(dir)
}

func verifyIdentityRekeyResponseKey(journal bootstrapstart.IdentityRekeyJournal, accepted bootstrapstart.AcceptedIdentity, bundleWire, privateWire []byte) error {
	bundle, err := hostenroll.ParsePublicBundle(bundleWire)
	if err != nil || bundle.ControllerResponsePublicKey != journal.HostObservation.ResponseKey {
		return identityrekey.ErrHostStateHandoff
	}

	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privateWire)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return identityrekey.ErrHostStateHandoff
	}
	defer clear(key)
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	if !bytes.Equal(derived, key) || base64.StdEncoding.EncodeToString(derived[ed25519.SeedSize:]) != bundle.ControllerResponsePublicKey {
		return identityrekey.ErrHostStateHandoff
	}
	reference := slices.IndexFunc(accepted.MaterialReferences, func(reference bootstrap.SecretReference) bool {
		return reference.TargetFile == accepted.Slot+"-response.key"
	})
	if reference < 0 || controllerSHA256(privateWire) != accepted.MaterialReferences[reference].SHA256 {
		return identityrekey.ErrHostStateHandoff
	}
	return nil
}

func verifyIdentityRekeyResponseBundle(journal bootstrapstart.IdentityRekeyJournal, wire []byte) error {
	bundle, err := hostenroll.ParsePublicBundle(wire)
	if err != nil || bundle.ControllerResponsePublicKey != journal.HostObservation.ResponseKey {
		return identityrekey.ErrHostStateHandoff
	}
	return nil
}
