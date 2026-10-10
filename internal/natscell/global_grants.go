package natscell

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nkeys"
)

// GlobalControllerPublishes is what a controller in the global home region
// publishes beyond its regional grants: the global-scope authority lease and
// journal (ts.control.global.>) and the fenced global state records
// (ts.global.v1.>). The controller role carries them in every region, so a
// credential never depends on which region is the home: only the global lease
// holder writes, fenced by the lease and the stream's compare-and-set, and
// neither namespace crosses a region link, so outside the home they reach
// nothing.
func GlobalControllerPublishes() []string {
	return []string{protocol.Control(protocol.GlobalScope, ">"), protocol.GlobalState(">")}
}

// ErrMissingGlobalGrants means the controller's NATS credentials predate the
// global home grants. Re-issue their signed material before starting the
// global home controller.
var ErrMissingGlobalGrants = errors.New("controller NATS credentials lack the global home publish grants")

// ValidateGlobalControllerPermissions checks, before the global authority
// starts, that this controller's credentials may publish every global home
// subject. Without the check a permission violation surfaces only as a
// publish timeout that the controller start-up retry loop never escapes.
// Credentials without publish restrictions (unrestricted test users) pass.
func ValidateGlobalControllerPermissions(cfg Config) error {
	switch {
	case cfg.CredentialsFile != "":
		claim, _, err := credentialUser(cfg.CredentialsFile)
		if err != nil {
			return fmt.Errorf("controller credentials: %w", err)
		}
		return globalPublishGranted(claim.Pub.Allow, claim.Pub.Deny)
	case cfg.NKeySeedFile != "" && cfg.Embedded != nil && len(cfg.Embedded.Users) != 0:
		data, err := readPrivateFile(cfg.NKeySeedFile, 4096)
		if err != nil {
			return fmt.Errorf("controller NKey seed: %w", err)
		}
		pair, err := nkeys.ParseDecoratedUserNKey(data)
		clear(data)
		if err != nil {
			return fmt.Errorf("controller NKey seed: %w", err)
		}
		public, err := pair.PublicKey()
		pair.Wipe()
		if err != nil {
			return err
		}
		for _, user := range cfg.Embedded.Users {
			if user.PublicKey == public {
				if user.Role != "controller" || !user.Global {
					return ErrMissingGlobalGrants
				}
				return nil
			}
		}
		return ErrMissingGlobalGrants
	}
	return nil
}

// ValidateGlobalControllerCredentialBytes checks the home grants before
// offline credentials are admitted into a signed material generation.
func ValidateGlobalControllerCredentialBytes(data []byte) error {
	claim, _, err := credentialUserBytes(data)
	if err != nil {
		return err
	}
	return globalPublishGranted(claim.Pub.Allow, claim.Pub.Deny)
}

// globalPublishGranted checks JWT publish permissions against every global
// home namespace. An absent allow list means every subject not denied; a
// present one must cover the namespace. Any deny that can match a subject in
// the namespace makes a publish fail.
func globalPublishGranted(allow, deny []string) error {
	for _, subject := range GlobalControllerPublishes() {
		if len(allow) != 0 && !grantsCover(allow, subject) || grantsTouch(deny, subject) {
			return fmt.Errorf("%w: %q", ErrMissingGlobalGrants, subject)
		}
	}
	return nil
}

// grantsCover reports whether some grant matches every subject that subject
// (itself possibly ending in ">") can name.
func grantsCover(grants []string, subject string) bool {
	return slices.ContainsFunc(grants, func(grant string) bool { return subjectCovers(grant, subject) })
}

// grantsTouch reports whether a deny grant overlaps subject at all: whether
// some concrete subject matches both patterns.
func grantsTouch(grants []string, subject string) bool {
	return slices.ContainsFunc(grants, func(grant string) bool { return subjectsIntersect(grant, subject) })
}

// subjectsIntersect reports whether two subject patterns can match a common
// concrete subject. "*" matches one token and ">" one or more trailing ones.
func subjectsIntersect(left, right string) bool {
	leftTokens, rightTokens := strings.Split(left, "."), strings.Split(right, ".")
	for index := 0; ; index++ {
		leftDone, rightDone := index >= len(leftTokens), index >= len(rightTokens)
		switch {
		case leftDone && rightDone:
			return true
		case leftDone || rightDone:
			return false
		}
		a, b := leftTokens[index], rightTokens[index]
		if a == ">" || b == ">" {
			return true
		}
		if a != "*" && b != "*" && a != b {
			return false
		}
	}
}

func subjectCovers(grant, subject string) bool {
	grantTokens, subjectTokens := strings.Split(grant, "."), strings.Split(subject, ".")
	for index, token := range grantTokens {
		if token == ">" {
			return true
		}
		if index >= len(subjectTokens) {
			return false
		}
		switch candidate := subjectTokens[index]; {
		case candidate == ">":
			return false
		case token == "*" || token == candidate:
		default:
			return false
		}
	}
	return len(grantTokens) == len(subjectTokens)
}
