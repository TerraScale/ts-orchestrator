package hostagent

import (
	"context"
	"encoding/json/v2"
	"errors"
	"golang.org/x/sys/unix"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

// Linux FS_IMMUTABLE_FL from linux/fs.h; retained across service restart.
const sourceImmutableFlag = 0x00000010

type cutSealRecord struct {
	RetirementSHA256         string
	SourceStateReceiptSHA256 string
	PlanSHA256               string
	Tree                     cutTree
	StoppedAt                time.Time
}

// ResumeLocalStorageTransitionCut is the privileged post-retirement source
// operation. It never admits retirement, broadens a command, or opens a broker.
// A durable original host plan and irreversible original-launch retirement are
// required on every retry, including after the ordinary source lease is gone.
func ResumeLocalStorageTransitionCut(ctx context.Context, l *Lifecycle, node string, public, signed []byte) ([]byte, error) {
	if ctx == nil || l == nil || os.Geteuid() != 0 {
		return nil, errors.New("hostagent: trusted source copy receiver required")
	}
	a, err := parseBootstrapAuthority(node, public, signed)
	if err != nil {
		return nil, err
	}
	v, _, found, err := a.readStorageTransition(ctx, false)
	if err != nil || !found {
		return nil, err
	}
	p, err := v.Plan()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, p.ExpiresAt)
	defer cancel()
	if p.Source.NodeID != node {
		return nil, nil
	}
	proof, err := initialgrant.VerifyProof(node, public, signed)
	if err != nil || proof == nil {
		return nil, errors.New("hostagent: original source proof required")
	}
	identity := proof.Identity()
	if identity.GrantSHA256 != p.Source.BootstrapGrantSHA256 || identity.StoreScopeSHA256 != p.Source.StoreScopeSHA256 || proof.Config().Broker.StoreDir != p.Source.StoreDir {
		return nil, errors.New("hostagent: original store differs from copy plan")
	}
	guard, err := nodeauthority.NewInitialR1Guard(nodeauthority.InitialR1AdmissionDirectory, identity)
	if err != nil {
		return nil, err
	}
	if err := guard.Check(ctx); !errors.Is(err, nodeauthority.ErrInitialR1Retired) {
		if err == nil {
			return nil, nil
		}
		return nil, err
	}
	directory := filepath.Join(l.dataRoot, hostmanifest.TsNodeComponentName, "command-journal")
	epochs, err := nodeauthority.NewEpochStore(directory, node)
	if err != nil {
		return nil, err
	}
	defer epochs.Close()
	if _, err := epochs.ResumeStorageTransitionPlan(ctx, v.Digest()); err != nil {
		return nil, err
	}
	retirement, err := guard.Retirement(ctx)
	if err != nil {
		return nil, err
	}
	pinRaw, err := epochs.AcknowledgeStorageTransitionPlan(ctx, v.Digest(), nil)
	if err != nil {
		return nil, err
	}
	pin, err := controltransition.VerifyPinReceipt(v, pinRaw)
	if err != nil {
		return nil, err
	}
	if retirement.CommandID != pin.CommandID || retirement.PreviousManifestSHA256 != p.Source.InitialManifestSHA256 || retirement.ReplacementManifestSHA256 != p.Source.CaptureManifestSHA256 {
		return nil, errors.New("hostagent: source retirement differs from admitted transition")
	}
	retirementRaw, err := json.Marshal(retirement)
	if err != nil {
		return nil, err
	}
	retirementDigest := controltransition.Digest(retirementRaw)
	stopped, ok := l.systemd.(interface {
		UnitStopped(context.Context, string) (bool, error)
	})
	if !ok {
		return nil, errors.New("hostagent: complete service stop observation required")
	}
	unit := ""
	sourceVolume, sourceUser := "", ""
	for _, spec := range a.grant.Manifest.Components {
		_, initial, err := initialgrant.ComponentConfig(spec)
		if err != nil {
			return nil, err
		}
		if initial {
			if unit != "" {
				return nil, errors.New("hostagent: duplicate original service")
			}
			unit = UnitName(spec.Name)
			sourceVolume, sourceUser = spec.DataVolume, spec.User
		}
	}
	if unit == "" {
		return nil, errors.New("hostagent: original service missing")
	}
	l.mutex.Lock()
	defer l.mutex.Unlock()
	live := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := v.Check(time.Now()); err != nil {
			return err
		}
		if err := guard.Check(ctx); !errors.Is(err, nodeauthority.ErrInitialR1Retired) {
			return errors.New("hostagent: source retirement unavailable")
		}
		return nil
	}
	if err := live(); err != nil {
		return nil, err
	}
	// The state producer must have fenced ordinary clients before recording
	// its independently signed complete stream/consumer observation.
	stateRaw, err := bootstrapcredentials.ReadFile(filepath.Join(directory, "storage-transition-source-state.json"), true, controltransition.MaximumBytes)
	if err != nil {
		return nil, err
	}
	state, err := controltransition.VerifySourceStateReceipt(v, stateRaw)
	if err != nil || state.ObservedAt.After(time.Now()) {
		return nil, errors.New("hostagent: quiescent source state unavailable")
	}
	stateDigest := controltransition.Digest(stateRaw)
	// Reissue stop after unknown outcomes; never infer quiescence from a timeout.
	if err := l.systemd.StopUnit(ctx, unit); err != nil {
		return nil, err
	}
	quiet, err := stopped.UnitStopped(ctx, unit)
	if err != nil {
		return nil, err
	}
	if !quiet {
		return nil, errors.New("hostagent: original broker has surviving processes")
	}
	account, err := user.Lookup(sourceUser)
	if err != nil {
		return nil, err
	}
	sourceUID, err := strconv.ParseUint(account.Uid, 10, 32)
	if err != nil || sourceUID == 0 {
		return nil, errors.New("hostagent: dedicated source service account required")
	}
	source, err := openCutRootOwned(p.Source.StoreDir, false, sourceVolume, uint32(sourceUID))
	if err != nil {
		return nil, err
	}
	defer source.Close()
	observed, err := inspectCutTree(ctx, source, p.Limits)
	if err != nil {
		return nil, err
	}
	sealPath := filepath.Join(directory, "storage-transition-source-seal.json")
	seal := cutSealRecord{RetirementSHA256: retirementDigest, SourceStateReceiptSHA256: stateDigest, PlanSHA256: v.Digest(), Tree: observed, StoppedAt: time.Now().UTC()}
	if raw, err := readCutRecord(sealPath, controltransition.MaximumBytes); err == nil {
		if json.Unmarshal(raw, &seal, json.RejectUnknownMembers(true)) != nil || seal.RetirementSHA256 != retirementDigest || seal.SourceStateReceiptSHA256 != stateDigest || state.ObservedAt.After(seal.StoppedAt) || seal.PlanSHA256 != v.Digest() || seal.Tree != observed || v.Check(seal.StoppedAt) != nil {
			return nil, errors.New("hostagent: original sealed store changed")
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	// Root ownership and read-only modes seal bytes from the retired dedicated
	// service account; the durable launch guard prevents managed reopening.
	if err := sealCutTree(ctx, source, p.Limits); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(seal)
	if err != nil {
		return nil, err
	}
	if err := retainStorageTransitionPlan(ctx, sealPath, raw, live); err != nil {
		return nil, err
	}
	receiptPath := filepath.Join(directory, "storage-transition-source-copy.json")
	if raw, err := readCutRecord(receiptPath, controltransition.CutReceiptMaximumBytes); err == nil {
		r, err := controltransition.VerifyCutReceipt(v, raw)
		if err != nil || r.RetirementSHA256 != retirementDigest || r.SourceStateReceiptSHA256 != stateDigest || r.StoreSHA256 != observed.SHA256 || r.SourceDevice != observed.Device || r.SourceInode != observed.Inode {
			return nil, errors.New("hostagent: retained source copy receipt differs")
		}
		return raw, live()
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	copyParent, err := openCutRoot(filepath.Dir(p.Source.CaptureDir), false)
	if err != nil {
		return nil, err
	}
	defer copyParent.Close()
	if err := copyParent.Mkdir(filepath.Base(p.Source.CaptureDir), 0700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	copyRoot, err := openCutRoot(p.Source.CaptureDir, true)
	if err != nil {
		return nil, err
	}
	defer copyRoot.Close()
	if err := copyCutTree(ctx, source, copyRoot, p.Limits); err != nil {
		return nil, err
	}
	copied, err := inspectCutTree(ctx, copyRoot, p.Limits)
	if err != nil {
		return nil, err
	}
	after, err := inspectCutTree(ctx, source, p.Limits)
	if err != nil {
		return nil, err
	}
	if after != observed || copied.SHA256 != observed.SHA256 || copied.Files != observed.Files || copied.Bytes != observed.Bytes {
		return nil, errors.New("hostagent: source working copy differs")
	}
	if err := syncCutDirectory(copyParent, "."); err != nil {
		return nil, err
	}
	if err := live(); err != nil {
		return nil, err
	}
	quiet, err = stopped.UnitStopped(ctx, unit)
	if err != nil || !quiet {
		return nil, errors.New("hostagent: original broker stop proof lost")
	}
	d, _, err := a.storageTransitionDelivery()
	if err != nil {
		return nil, err
	}
	key, err := bootstrapcredentials.ReadFile(d.ReceiptPrivateKeyFile, true, 32<<10)
	if err != nil {
		return nil, err
	}
	signer, err := security.ParseCommandSignatureSignerPEM(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	defer signer.Close()
	r := controltransition.CutReceipt{RetirementSHA256: retirementDigest, SourceStateReceiptSHA256: stateDigest, Version: 1, Phase: "source-store-copied", PlanSHA256: v.Digest(), NodeID: node, BootstrapGrantSHA256: p.Source.BootstrapGrantSHA256, StoreScopeSHA256: p.Source.StoreScopeSHA256, StoreSHA256: observed.SHA256, CopySHA256: copied.SHA256, SourceDevice: observed.Device, SourceInode: observed.Inode, Files: observed.Files, Bytes: observed.Bytes, StoppedAt: seal.StoppedAt, CopiedAt: time.Now().UTC()}
	receipt, err := controltransition.SignCutReceipt(signer, v, r)
	if err != nil {
		return nil, err
	}
	if err := retainStorageTransitionPlan(ctx, receiptPath, receipt, live); err != nil {
		return nil, err
	}
	return receipt, nil
}

func sealCutTree(ctx context.Context, root *os.Root, limits controltransition.Limits) error {
	err := walkCutTree(ctx, root, limits.MaxStoreFiles, func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		info, err := root.Lstat(name)
		if err != nil {
			return err
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return errors.New("hostagent: unsafe seal entry")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("hostagent: seal ownership unavailable")
		}
		if stat.Uid != 0 || stat.Gid != 0 {
			if err := root.Chown(name, 0, 0); err != nil {
				return err
			}
		}
		mode := os.FileMode(0400)
		if d.IsDir() {
			mode = 0500
		}
		if info.Mode().Perm() != mode {
			if err := root.Chmod(name, mode); err != nil {
				return err
			}
		}
		f, err := root.Open(name)
		if err != nil {
			return err
		}
		return errors.Join(f.Sync(), f.Close())
	})
	if err != nil {
		return err
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	flags, err := unix.IoctlGetInt(int(directory.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil {
		return errors.Join(errors.New("hostagent: immutable source sealing unavailable"), err)
	}
	if flags&sourceImmutableFlag == 0 {
		if err := unix.IoctlSetPointerInt(int(directory.Fd()), unix.FS_IOC_SETFLAGS, flags|sourceImmutableFlag); err != nil {
			return errors.Join(errors.New("hostagent: immutable source sealing refused"), err)
		}
	}
	observed, err := unix.IoctlGetInt(int(directory.Fd()), unix.FS_IOC_GETFLAGS)
	if err != nil || observed&sourceImmutableFlag == 0 {
		return errors.New("hostagent: immutable source seal unconfirmed")
	}
	return directory.Sync()
}

// VerifyStorageTransitionCopy checks the unopened capture directory against
// the signed source copy receipt. Capture must call this before broker startup;
// later TTL/retention changes still need independent final-state comparison.
func VerifyStorageTransitionCopy(ctx context.Context, v controltransition.VerifiedPlan, raw []byte) error {
	if ctx == nil {
		return errors.New("hostagent: capture verification context required")
	}
	if err := v.Check(time.Now()); err != nil {
		return err
	}
	r, err := controltransition.VerifyCutReceipt(v, raw)
	if err != nil {
		return err
	}
	p, err := v.Plan()
	if err != nil {
		return err
	}
	root, err := openCutRoot(p.Source.CaptureDir, false)
	if err != nil {
		return err
	}
	defer root.Close()
	tree, err := inspectCutTree(ctx, root, p.Limits)
	if err != nil {
		return err
	}
	if tree.SHA256 != r.CopySHA256 || tree.Files != r.Files || tree.Bytes != r.Bytes {
		return errors.New("hostagent: capture copy differs from signed source")
	}
	return ctx.Err()
}

// CaptureCopyIdentity is a byte-only tree identity. It does not assert that
// reopening NATS preserved source stream semantics or consumer state.
type CaptureCopyIdentity struct {
	SHA256 string
	Files  int64
	Bytes  int64
}

func InspectStorageTransitionCopy(ctx context.Context, v controltransition.VerifiedPlan) (CaptureCopyIdentity, error) {
	if ctx == nil {
		return CaptureCopyIdentity{}, errors.New("hostagent: copy context required")
	}
	if err := v.Check(time.Now()); err != nil {
		return CaptureCopyIdentity{}, err
	}
	p, err := v.Plan()
	if err != nil {
		return CaptureCopyIdentity{}, err
	}
	root, err := openCutRoot(p.Source.CaptureDir, false)
	if err != nil {
		return CaptureCopyIdentity{}, err
	}
	defer root.Close()
	tree, err := inspectCutTree(ctx, root, p.Limits)
	if err != nil {
		return CaptureCopyIdentity{}, err
	}
	return CaptureCopyIdentity{SHA256: tree.SHA256, Files: tree.Files, Bytes: tree.Bytes}, nil
}

// ReadFile intentionally hides filesystem failures. Preserve only an explicit
// absent leaf here, so first execution can create its immutable stage record;
// present files still use the protected descriptor-relative credential reader.
func readCutRecord(path string, maximum int64) ([]byte, error) {
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	return bootstrapcredentials.ReadFile(path, true, maximum)
}
