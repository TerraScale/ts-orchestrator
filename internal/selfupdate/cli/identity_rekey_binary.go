package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/selfupdate"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go/jetstream"
	"golang.org/x/sys/unix"
)

// VerifyIdentityRekeyCandidate admits a proposed signed binary without requiring
// old current/known-good binaries to understand the new accepted contract.
func VerifyIdentityRekeyCandidate(ctx context.Context, accepted bootstrapstart.AcceptedIdentity, inputs bootstrapstart.TrustInputs, candidate string, receipt, delegation []byte, now time.Time) error {
	return verifyIdentityRekeyCandidate(ctx, accepted, inputs, candidate, receipt, delegation, now, 0, false)
}

func verifyIdentityRekeyCandidate(ctx context.Context, accepted bootstrapstart.AcceptedIdentity, inputs bootstrapstart.TrustInputs, candidate string, receipt, delegation []byte, now time.Time, owner uint32, unsafeAncestors bool) error {
	if err := accepted.Validate(); err != nil {
		return err
	}
	identity := trust.ChainIdentity{DeploymentID: accepted.DeploymentID, Environment: accepted.Environment, Cell: strings.ToLower(accepted.Cell)}
	if inputs.ChainIdentity != identity {
		return trust.ErrScopeMismatch
	}
	roots, err := trust.VerifyRootChain(inputs.Genesis, identity, inputs.Chain)
	if err != nil {
		return err
	}
	return verifyIdentityRekeyCandidateRoots(ctx, accepted, candidate, receipt, delegation, now, owner, unsafeAncestors, roots.Current)
}

func verifyIdentityRekeyCandidateRoots(ctx context.Context, accepted bootstrapstart.AcceptedIdentity, candidate string, receipt, delegation []byte, now time.Time, owner uint32, unsafeAncestors bool, roots trust.Keyring) error {
	policy := selfupdate.ReceiptPolicy{Roots: roots, Environment: accepted.Environment, Cell: accepted.Cell, Architecture: accepted.Binary.Architecture}
	verified, err := policy.Verify(receipt, delegation, now)
	if err != nil {
		return err
	}
	pin := verified.Receipt()
	if pin.SHA256 != accepted.Binary.SHA256 || pin.Bytes != accepted.Binary.Size || pin.GOARCH != accepted.Binary.Architecture {
		return selfupdate.ErrInvalid
	}
	if err := verifyCandidateOwnership(candidate, owner, unsafeAncestors); err != nil {
		return err
	}
	if err := bootstrapstart.VerifyIdentityRekeyBinaryFile(candidate, accepted.Binary); err != nil {
		return err
	}
	return checkAcceptedBinary(ctx, candidate, accepted)
}

// VerifyCommittedIdentityRekeyCandidate requires independently observed shared
// commitment before replaying the exact binary authorization.
func VerifyCommittedIdentityRekeyCandidate(ctx context.Context, verified bootstrapstart.VerifiedIdentityRekey, inputs bootstrapstart.TrustInputs, candidate string, receipt, delegation []byte, now time.Time) error {
	current, err := verified.VerifyCurrent(inputs, now)
	if err != nil {
		return err
	}
	return verifyIdentityRekeyCandidateRoots(ctx, current.Accepted(), candidate, receipt, delegation, current.InstallationTime(now), 0, false, current.InstallationRoots(inputs))
}

// InstallIdentityRekeyBinary requires the exact durable rooted plan and a stopped
// controller. It installs both fixed release links and never starts the service.
func InstallIdentityRekeyBinary(ctx context.Context, journal bootstrapstart.IdentityRekeyJournal, candidate string, receipt, delegation []byte, now time.Time, js jetstream.JetStream) error {
	present, err := bootstrapstart.IdentityRekeyJournalPresent()
	if err != nil {
		return err
	}
	if !present {
		return errors.New("identity rekey binary installation requires its durable root journal")
	}
	verified, inputs, err := bootstrapstart.VerifyCommittedIdentityRekeyInstall(ctx, journal, js, now)
	if err != nil {
		return err
	}
	accepted := verified.Accepted()
	now = verified.InstallationTime(now)
	if err := VerifyCommittedIdentityRekeyCandidate(ctx, verified, inputs, candidate, receipt, delegation, now); err != nil {
		return err
	}
	policy := selfupdate.ReceiptPolicy{Roots: verified.AcceptedRoots(), Environment: accepted.Environment, Cell: accepted.Cell, Architecture: accepted.Binary.Architecture}
	check := func(path string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		present, err := bootstrapstart.IdentityRekeyJournalPresent()
		if err != nil || !present {
			return errors.Join(err, bootstrapstart.ErrIdentityRekeyJournal)
		}
		fresh, roots, err := bootstrapstart.VerifyCommittedIdentityRekeyInstall(ctx, journal, js, time.Now().UTC())
		if err != nil {
			return err
		}
		if err := VerifyCommittedIdentityRekeyCandidate(ctx, fresh, roots, path, receipt, delegation, time.Now().UTC()); err != nil {
			return err
		}
		return verifyControllerStopped(ctx)
	}
	return selfupdate.InstallIdentityRekeyBaseline(selfupdate.NewLayout(selfupdate.DefaultRoot), candidate, receipt, delegation, policy, now, check)
}

func verifyControllerStopped(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "systemctl", "show", "--no-pager", "--property=ActiveState,SubState,MainPID,ControlPID", selfupdate.ControllerUnit).Output()
	if err != nil {
		return fmt.Errorf("observe stopped controller: %w", err)
	}
	return controllerStoppedState(output)
}

func controllerStoppedState(output []byte) error {
	state := map[string]string{}
	for line := range strings.SplitSeq(strings.TrimSpace(string(output)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok || state[key] != "" {
			return selfupdate.ErrInvalid
		}
		state[key] = value
	}
	if len(state) != 4 || state["ActiveState"] != "inactive" || state["SubState"] != "dead" || state["MainPID"] != "0" || state["ControlPID"] != "0" {
		return errors.New("identity rekey binary installation requires the controller stopped")
	}
	return nil
}

func verifyCandidateOwnership(path string, owner uint32, unsafeAncestors bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return selfupdate.ErrUnsafe
	}
	dir, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	for component := range strings.SplitSeq(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if component == "" {
			continue
		}
		next, err := unix.Openat(dir, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(dir)
		if err != nil {
			return err
		}
		dir = next
		var stat unix.Stat_t
		if !unsafeAncestors && (unix.Fstat(dir, &stat) != nil || stat.Uid != owner || stat.Mode&0o022 != 0) {
			unix.Close(dir)
			return selfupdate.ErrUnsafe
		}
	}
	defer unix.Close(dir)
	fd, err := unix.Openat(dir, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != owner || stat.Nlink != 1 || stat.Mode&0o022 != 0 || stat.Mode&0o111 == 0 {
		return selfupdate.ErrUnsafe
	}
	return nil
}
