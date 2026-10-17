package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/identityrekey"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sys/unix"
)

type identityMaterialPredecessors struct {
	installed, durable string
	materials          map[string]bootstrap.SecretReference
	responsePublic     string
}

func identityRekeyMaterialTarget(verified VerifiedIdentityRekey, inputs TrustInputs, now time.Time) (GenerationTarget, []byte, identityMaterialPredecessors, error) {
	current, err := verified.VerifyCurrent(inputs, now)
	if err != nil {
		return GenerationTarget{}, nil, identityMaterialPredecessors{}, err
	}
	if err := identityrekey.ValidatePreviousMaterialPins(current.journal.PreviousMaterialSHA256); err != nil {
		return GenerationTarget{}, nil, identityMaterialPredecessors{}, err
	}
	accepted := current.Accepted()
	target, err := GenerationTargetFromAccepted(accepted)
	if err != nil {
		return GenerationTarget{}, nil, identityMaterialPredecessors{}, err
	}
	wire := current.Values()[2]
	chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
	if err != nil {
		return GenerationTarget{}, nil, identityMaterialPredecessors{}, err
	}
	generations, err := target.VerifyChain(chain, current.InstallationRoots(inputs), current.InstallationTime(now))
	if err != nil || generations[len(generations)-1].Fingerprint() != accepted.MaterialGenerationSHA256 {
		return GenerationTarget{}, nil, identityMaterialPredecessors{}, errors.Join(ErrMaterial, err)
	}
	refs := materialReferences(accepted, nil)
	for _, ref := range generations[len(generations)-1].Generation().Secrets {
		if (ref.Slot == "" || ref.Slot == accepted.Slot) && refs[ref.TargetFile] != ref {
			return GenerationTarget{}, nil, identityMaterialPredecessors{}, ErrMaterial
		}
	}
	return target, wire, identityMaterialPredecessors{installed: current.journal.PreviousMaterialSHA256["installed"],
		durable: current.journal.PreviousMaterialSHA256["durable"], materials: refs, responsePublic: current.journal.HostObservation.ResponseKey}, nil
}

func (store MaterialStore) VerifyIdentityRekeyMaterialPredecessors(verified VerifiedIdentityRekey, inputs TrustInputs, now time.Time) error {
	_, chain, previous, err := identityRekeyMaterialTarget(verified, inputs, now)
	if err != nil {
		return err
	}
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	return store.verifyIdentityMaterialPredecessors(dir, chain, previous)
}

// AdoptIdentityRekeyGeneration replaces the complete baseline authorized by
// the root checkpoint. Ordinary generation adoption stays strict.
func (store MaterialStore) AdoptIdentityRekeyGeneration(ctx context.Context, verified VerifiedIdentityRekey, inputs TrustInputs,
	files map[string][]byte, config []byte, beforeEffect func(context.Context) error, sourceLive func() error, now time.Time,
) error {
	return store.adoptIdentityRekeyGeneration(ctx, NewMarkerStore(), verified, inputs, files, config, beforeEffect, sourceLive, now)
}

func (store MaterialStore) adoptIdentityRekeyGeneration(ctx context.Context, markers MarkerStore, verified VerifiedIdentityRekey, inputs TrustInputs,
	files map[string][]byte, config []byte, beforeEffect func(context.Context) error, sourceLive func() error, now time.Time,
) error {
	var err error
	store, err = store.identityRekeyPublication(ctx, markers, verified, inputs, beforeEffect, sourceLive)
	if err != nil {
		return err
	}
	target, chain, previous, err := identityRekeyMaterialTarget(verified, inputs, now)
	if err != nil {
		return err
	}
	return store.adoptGeneration(target, verified.InstallationRoots(inputs), chain, files, config, verified.InstallationTime(now), &previous)
}

func (store MaterialStore) FinishIdentityRekeyMaterialAdoption(ctx context.Context, verified VerifiedIdentityRekey, inputs TrustInputs, configPath string, beforeEffect func(context.Context) error, sourceLive func() error, now time.Time) error {
	return store.finishIdentityRekeyMaterialAdoption(ctx, NewMarkerStore(), verified, inputs, configPath, beforeEffect, sourceLive, now)
}

func (store MaterialStore) finishIdentityRekeyMaterialAdoption(ctx context.Context, markers MarkerStore, verified VerifiedIdentityRekey, inputs TrustInputs, configPath string, beforeEffect func(context.Context) error, sourceLive func() error, now time.Time) error {
	var err error
	store, err = store.identityRekeyPublication(ctx, markers, verified, inputs, beforeEffect, sourceLive)
	if err != nil {
		return err
	}
	target, chain, previous, err := identityRekeyMaterialTarget(verified, inputs, now)
	if err != nil {
		return err
	}
	if err := store.VerifyIdentityRekeyMaterialAdoption(verified, inputs, now); err != nil {
		return err
	}
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	if err := store.verifyIdentityMaterialPredecessors(dir, chain, previous); err != nil {
		return err
	}
	return store.finish(dir, target, verified.InstallationRoots(inputs), configPath, verified.InstallationTime(now), &previous, nil)
}

func verifyInstalledGenerationChain(installed, chainWire []byte, chain []trust.Envelope, previous *identityMaterialPredecessors) error {
	if previous != nil {
		if bytes.Equal(installed, chainWire) || digest(installed) == previous.installed {
			return nil
		}
		return ErrMaterial
	}
	held, err := bootstrap.DecodeMaterialGenerationChain(installed)
	if err != nil || !chainIs(held, chainWire) && !bootstrap.ExtendsMaterialGenerationChain(chain, held) {
		return ErrMaterial
	}
	return nil
}

func (store MaterialStore) verifyIdentityMaterialPredecessors(dir int, chainWire []byte, previous identityMaterialPredecessors) error {
	if !markerDigestRE.MatchString(previous.installed) || !markerDigestRE.MatchString(previous.durable) || len(chainWire) == 0 || store.chainCopy == "" {
		return ErrMaterial
	}
	installed, err := readUnpinned(dir, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
	if err != nil || !bytes.Equal(installed, chainWire) && digest(installed) != previous.installed {
		return errors.Join(ErrMaterial, err)
	}
	copyDir, err := openMaterialDirectory(filepath.Dir(store.chainCopy), uint32(os.Geteuid()), uint32(os.Getegid()), 0o755, store.allowUnsafeAncestors)
	if err != nil {
		return err
	}
	defer unix.Close(copyDir)
	fd, err := unix.Openat(copyDir, filepath.Base(store.chainCopy), unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), store.chainCopy)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o644 ||
		stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) || stat.Nlink != 1 || stat.Size <= 0 || stat.Size > maxGenerationChainBytes {
		return ErrMaterial
	}
	wire, err := io.ReadAll(io.LimitReader(file, maxGenerationChainBytes+1))
	if err != nil || int64(len(wire)) != stat.Size || !bytes.Equal(wire, chainWire) && digest(wire) != previous.durable {
		return errors.Join(ErrMaterial, err)
	}
	return nil
}

// VerifyIdentityRekeyInstall verifies proposed authority from fixed baked
// genesis and the installed chain, without interpreting the predecessor.
func VerifyIdentityRekeyInstall(journal IdentityRekeyJournal, now time.Time) (VerifiedIdentityRekey, TrustInputs, error) {
	return verifyIdentityRekeyInstall(NewMarkerStore(), bakedStore{
		directory: BakedDirectory, chainFile: RootChainFile, ownerUID: 0, ownerGID: 0,
	}, journal, now, false)
}

// VerifyStagedIdentityRekeyInstall refuses any operation not already durably
// reviewed by root, including an otherwise valid proposal with no journal.
func VerifyStagedIdentityRekeyInstall(journal IdentityRekeyJournal, now time.Time) (VerifiedIdentityRekey, TrustInputs, error) {
	return verifyIdentityRekeyInstall(NewMarkerStore(), bakedStore{
		directory: BakedDirectory, chainFile: RootChainFile, ownerUID: 0, ownerGID: 0,
	}, journal, now, true)
}

func verifyIdentityRekeyInstall(markers MarkerStore, baked bakedStore, journal IdentityRekeyJournal, now time.Time, requireStaged bool) (VerifiedIdentityRekey, TrustInputs, error) {
	fail := func(err error) (VerifiedIdentityRekey, TrustInputs, error) {
		return VerifiedIdentityRekey{}, TrustInputs{}, err
	}
	accepted, err := DecodeAcceptedIdentity(journal.AcceptedWire)
	if err != nil {
		return fail(err)
	}
	inputs, err := baked.loadTrustInputs(accepted)
	if err != nil {
		return fail(err)
	}
	verified, err := verifyIdentityRekeyJournal(journal, inputs, now, false)
	if err != nil {
		return fail(err)
	}
	return verifyIdentityRekeyInstallPredecessor(markers, journal, verified, inputs, requireStaged)
}

func verifyIdentityRekeyInstallPredecessor(markers MarkerStore, journal IdentityRekeyJournal, verified VerifiedIdentityRekey, inputs TrustInputs, requireStaged bool) (VerifiedIdentityRekey, TrustInputs, error) {
	fail := func(err error) (VerifiedIdentityRekey, TrustInputs, error) {
		return VerifiedIdentityRekey{}, TrustInputs{}, err
	}
	existing, readErr := markers.readIdentityRekeyJournal()
	if readErr != nil && (requireStaged || !errors.Is(readErr, os.ErrNotExist)) {
		return fail(readErr)
	}
	if readErr == nil {
		old, err := encodeIdentityRekeyJournal(existing)
		if err != nil {
			return fail(err)
		}
		proposed, err := encodeIdentityRekeyJournal(journal)
		if err != nil || !bytes.Equal(old, proposed) {
			if requireStaged {
				return fail(ErrIdentityRekeyJournal)
			}
			// Read-only successor preparation cannot replace the retained journal.
			accepted, err := markers.ReadIdentity()
			if err != nil || accepted.Origin != identityrekey.AcceptanceOriginRekey || accepted.OperationID == verified.Accepted().OperationID {
				return fail(ErrIdentityRekeyJournal)
			}
			wire, err := EncodeAcceptedIdentity(accepted)
			if err != nil || !bytes.Equal(wire, existing.AcceptedWire) || digest(wire) != journal.PreviousAcceptanceSHA256 {
				return fail(ErrAcceptancePredecessor)
			}
		}
	}
	dir, err := markers.openDirectory()
	if err != nil {
		return fail(err)
	}
	defer unix.Close(dir)
	previous, err := markers.readIdentityBytes(dir, markerName)
	if err != nil {
		return fail(err)
	}
	if digest(previous) != journal.PreviousAcceptanceSHA256 &&
		!(readErr == nil && bytes.Equal(previous, journal.AcceptedWire)) {
		return fail(ErrAcceptancePredecessor)
	}
	return verified, inputs, nil
}

// VerifyCommittedIdentityRekeyInstall requires both the fixed durable journal
// and independently authenticated shared commitment before local replay.
func VerifyCommittedIdentityRekeyInstall(ctx context.Context, journal IdentityRekeyJournal, js jetstream.JetStream, now time.Time) (VerifiedIdentityRekey, TrustInputs, error) {
	return verifyCommittedIdentityRekeyInstall(ctx, NewMarkerStore(), bakedStore{directory: BakedDirectory, chainFile: RootChainFile, ownerUID: 0, ownerGID: 0}, journal, js, now)
}

func verifyCommittedIdentityRekeyInstall(ctx context.Context, markers MarkerStore, baked bakedStore, journal IdentityRekeyJournal, js jetstream.JetStream, now time.Time) (VerifiedIdentityRekey, TrustInputs, error) {
	accepted, err := DecodeAcceptedIdentity(journal.AcceptedWire)
	if err != nil {
		return VerifiedIdentityRekey{}, TrustInputs{}, err
	}
	inputs, err := baked.loadTrustInputs(accepted)
	if err != nil {
		return VerifiedIdentityRekey{}, TrustInputs{}, err
	}
	verified, err := verifyIdentityRekeyJournal(journal, inputs, accepted.AcceptedAt, true)
	if err != nil {
		return VerifiedIdentityRekey{}, TrustInputs{}, err
	}
	verified, inputs, err = verifyIdentityRekeyInstallPredecessor(markers, journal, verified, inputs, true)
	if err != nil {
		return VerifiedIdentityRekey{}, TrustInputs{}, err
	}
	verified.committedJS, verified.committedContext, verified.committedMarkers = js, ctx, markers
	if js == nil {
		return VerifiedIdentityRekey{}, TrustInputs{}, ErrIdentityRekeyJournal
	}
	verified, err = verified.VerifyCurrent(inputs, now)
	return verified, inputs, err
}

// VerifyIdentityRekeyLaunchMaterial checks the four exact public launch inputs
// before installation. Their names never select a caller-owned destination.
func VerifyIdentityRekeyLaunchMaterial(accepted AcceptedIdentity, regionWire []byte, files map[string][]byte, now time.Time) error {
	inputs, err := LoadTrustInputs(accepted)
	if err != nil {
		return err
	}
	return verifyIdentityRekeyLaunchMaterial(accepted, inputs, regionWire, files, now)
}

func verifyIdentityRekeyLaunchMaterial(accepted AcceptedIdentity, inputs TrustInputs, regionWire []byte, files map[string][]byte, now time.Time) error {
	if accepted.Validate() != nil || len(accepted.LaunchMaterialSHA256) != len(acceptedLaunchNames) || len(files) != len(acceptedLaunchNames) ||
		digest(regionWire) != accepted.ConfigSHA256["oci-region.json"] {
		return ErrLaunchMaterial
	}
	for _, name := range acceptedLaunchNames {
		if len(files[name]) == 0 || digest(files[name]) != accepted.LaunchMaterialSHA256[name] {
			return ErrLaunchMaterial
		}
	}
	if err := validateHostLaunchInputs(files[HostEnrollmentFilename], files[OperatorSSHKeyFilename], accepted.Cell, accepted.Environment); err != nil {
		return err
	}
	expected, err := managedLaunchExpectation(regionWire, accepted.Cell, accepted.Environment)
	if err != nil {
		return err
	}
	_, err = release.VerifyImageCurrent(files[ManagedHostImageReceiptFilename], files[ManagedHostImageDelegationFilename], inputs.Roots.Current, expected, now)
	return err
}

// VerifyIdentityRekeyMaterialAdoption restricts interrupted native adoption to
// this operation's exact chain, including files in an uncommitted partial stage.
func (store MaterialStore) VerifyIdentityRekeyMaterialAdoption(rekey VerifiedIdentityRekey, inputs TrustInputs, now time.Time) error {
	target, chainWire, previous, err := identityRekeyMaterialTarget(rekey, inputs, now)
	if err != nil {
		return err
	}
	return store.verifyIdentityRekeyMaterialAdoption(target, rekey.InstallationRoots(inputs), chainWire, previous.materials, rekey.InstallationTime(now))
}

func (store MaterialStore) verifyIdentityRekeyMaterialAdoption(target GenerationTarget, roots trust.Keyring, chainWire []byte, refs map[string]bootstrap.SecretReference, now time.Time) error {
	chain, err := bootstrap.DecodeMaterialGenerationChain(chainWire)
	if err != nil {
		return err
	}
	verified, err := target.VerifyChain(chain, roots, now)
	if err != nil {
		return err
	}
	newest := verified[len(verified)-1]
	if newest.Fingerprint() != target.MaterialGenerationSHA256 {
		return ErrMaterial
	}
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	staging, err := store.openStaging(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(staging)
	names, err := stagedNames(staging)
	if err != nil {
		return err
	}
	committed := slices.Contains(names, MaterialGenerationsFile)
	if committed {
		staged, err := store.readStaged(staging, MaterialGenerationsFile, "", maxGenerationChainBytes)
		if err != nil || !bytes.Equal(staged, chainWire) {
			return ErrMaterial
		}
	}
	for _, name := range names {
		if name == MaterialGenerationsFile || committed && name == verifiedMaterialTemporary {
			continue
		}
		reference, exists := refs[name]
		if !committed && name == generationChainTemporary {
			reference.MaxBytes, exists = maxGenerationChainBytes, true
		}
		if !exists {
			return ErrMaterial
		}
		if !committed {
			// No commit record exists: Finish discards only owned target names.
			var stat unix.Stat_t
			if err := unix.Fstatat(staging, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil ||
				stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o7777 != 0o600 || stat.Nlink != 1 ||
				(stat.Uid != store.serviceUID || stat.Gid != store.serviceGID) &&
					(stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid())) || stat.Size < 0 || stat.Size > reference.MaxBytes {
				return ErrMaterial
			}
			continue
		}
		wire, err := store.readStaged(staging, name, reference.SHA256, reference.MaxBytes)
		clear(wire)
		if err != nil {
			return err
		}
	}
	return nil
}

// VerifyIdentityRekeyInstalledMaterial binds native restart verification to
// the exact installed operation and its already measured controller config.
func (store MaterialStore) VerifyIdentityRekeyInstalledMaterial(ctx context.Context, accepted AcceptedIdentity, roots trust.Keyring,
	chainWire, config []byte, now time.Time,
) (MaterialPins, error) {
	target, err := GenerationTargetFromAccepted(accepted)
	if err != nil {
		return MaterialPins{}, err
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(chainWire)
	if err != nil {
		return MaterialPins{}, err
	}
	verified, err := target.VerifyChain(chain, roots, now)
	if err != nil {
		return MaterialPins{}, err
	}
	if verified[len(verified)-1].Fingerprint() != accepted.MaterialGenerationSHA256 || digest(config) != accepted.ConfigSHA256["controller.json"] {
		return MaterialPins{}, ErrMaterial
	}
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return MaterialPins{}, err
	}
	defer unix.Close(dir)
	installed, err := readUnpinned(dir, MaterialGenerationsFile, store.serviceUID, store.serviceGID, maxGenerationChainBytes)
	if err != nil || !bytes.Equal(installed, chainWire) {
		return MaterialPins{}, ErrMaterial
	}
	pins, err := restartPins(dir, store.serviceUID, store.serviceGID, accepted, roots)
	if err != nil {
		return MaterialPins{}, err
	}
	pins.config = bytes.Clone(config)
	if err := store.VerifyRestart(ctx, accepted, pins); err != nil {
		return MaterialPins{}, err
	}
	return pins, nil
}

func (verified VerifiedIdentityRekey) VerifyLaunchMaterial(inputs TrustInputs, regionWire []byte, files map[string][]byte, now time.Time) error {
	current, err := verified.VerifyCurrent(inputs, now)
	if err != nil {
		return err
	}
	inputs.Roots.Current = current.InstallationRoots(inputs)
	return verifyIdentityRekeyLaunchMaterial(current.Accepted(), inputs, regionWire, files, current.InstallationTime(now))
}

func (store MaterialStore) identityRekeyPublication(ctx context.Context, markers MarkerStore, verified VerifiedIdentityRekey, inputs TrustInputs, beforeEffect func(context.Context) error, sourceLive func() error) (MaterialStore, error) {
	if ctx == nil || beforeEffect == nil || sourceLive == nil {
		return MaterialStore{}, ErrMaterial
	}
	store.restoreSeal = func() error {
		if err := identityRekeyOriginalLive(verified); err != nil {
			return err
		}
		if err := sourceLive(); err != nil {
			return err
		}
		return ctx.Err()
	}
	store.restoreCurrent = func([]trust.Envelope) error {
		if err := store.restoreSeal(); err != nil {
			return err
		}
		_, chain, previous, err := identityRekeyMaterialTarget(verified, inputs, time.Now())
		if err != nil {
			return err
		}
		if err := store.verifyIdentityRekeyInstalledPredecessor(ctx, markers, verified, chain, previous); err != nil {
			return err
		}
		if err := beforeEffect(ctx); err != nil {
			return err
		}
		return store.restoreSeal()
	}
	return store, store.publicationLive(nil)
}

func identityRekeyOriginalLive(verified VerifiedIdentityRekey) error {
	if !verified.IsVerified() {
		return ErrIdentityRekeyJournal
	}
	if verified.committedJS != nil {
		if verified.committedContext == nil {
			return ErrIdentityRekeyJournal
		}
		return verified.committedContext.Err()
	}
	if len(verified.journal.Values) <= 2 {
		return ErrIdentityRekeyJournal
	}
	for _, wire := range [][]byte{verified.journal.CheckpointWire, verified.journal.ResetWire, verified.journal.HostPlanWire} {
		envelope, err := trust.DecodeEnvelope(wire)
		if err != nil || !time.Now().Before(envelope.ExpiresAt) {
			return ErrIdentityRekeyJournal
		}
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(verified.journal.Values[2])
	if err != nil || !time.Now().Before(chain[len(chain)-1].ExpiresAt) {
		return ErrMaterial
	}
	return nil
}
