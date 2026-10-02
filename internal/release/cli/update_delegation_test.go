package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const testLineageBase = "89abcdef0123456789abcdef0123456789abcdef"

func TestSignUpdateDelegationThenAutoSignBinaryUpdate(t *testing.T) {
	fixture := newDelegationFixture(t)
	c := command{ctx: context.Background(), output: os.Stdout}
	delegationPath := filepath.Join(fixture.directory, "update-delegation.json")
	delegationArgs := []string{"--subject-public-key", fixture.leafPath, "--root-key", fixture.rootPath,
		"--signing-key", fixture.privatePath, "--environment", "canary", "--lineage-base", testLineageBase,
		"--cell", "GRU", "--arch", "amd64",
		"--issued-at", fixture.now.Add(-time.Minute).Format(time.RFC3339),
		"--expires-at", fixture.now.Add(24 * time.Hour).Format(time.RFC3339), "--out", delegationPath}
	tooLong := append([]string{}, delegationArgs...)
	tooLong[len(tooLong)-3] = fixture.now.Add(release.MaxUpdateDelegationLifetime + time.Hour).Format(time.RFC3339)
	tooLong[len(tooLong)-1] = filepath.Join(fixture.directory, "too-long.json")
	if err := c.signUpdateDelegation(tooLong); err == nil {
		t.Fatal("over-long update delegation signed")
	}
	if err := c.signUpdateDelegation(delegationArgs); err != nil {
		t.Fatalf("sign-update-delegation: %v", err)
	}

	leafKeyPath := filepath.Join(fixture.directory, "leaf.key")
	writePrivateKey(t, leafKeyPath, fixture.leafPrivate)
	candidatePath := filepath.Join(fixture.directory, "candidate.json")
	candidate, err := trust.EncodePayload(testBinaryReceipt())
	if err != nil {
		t.Fatal(err)
	}
	writeFixtureFile(t, candidatePath, candidate, 0o600)
	qualificationPath := filepath.Join(fixture.directory, "qualification.json")
	writeFixtureFile(t, qualificationPath, testQualificationWire(t), 0o600)
	binaryPath := filepath.Join(fixture.directory, "binary")
	writeFixtureFile(t, binaryPath, []byte("static binary"), 0o600)
	signedPath := filepath.Join(fixture.directory, "update-receipt.json")
	args := []string{"--candidate", candidatePath, "--binary", binaryPath, "--qualification", qualificationPath,
		"--update-delegation", delegationPath, "--root-key", fixture.rootPath, "--signing-key", leafKeyPath,
		"--environment", "canary", "--cell", "GRU", "--source-checkout", "/srv/checkout", "--out", signedPath}
	inspect := func(string, string, string) (binaryReceipt, error) { return testBinaryReceipt(), nil }
	check := func(release.Qualification, string) error { return nil }
	var gitCalls []string
	git := func(_ context.Context, args ...string) error {
		gitCalls = append(gitCalls, strings.Join(args, " "))
		return nil
	}
	if err := c.signBinaryUpdateWith(args, check, inspect, git); err != nil {
		t.Fatalf("sign-binary-update: %v", err)
	}
	if len(gitCalls) != 3 || !strings.Contains(gitCalls[1], "merge-base --is-ancestor "+testLineageBase+" "+testRevision) ||
		!strings.HasSuffix(gitCalls[2], testRevision+" refs/remotes/origin/main") {
		t.Fatalf("lineage checks = %q", gitCalls)
	}
	receiptWire, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatal(err)
	}
	delegationWire, err := os.ReadFile(delegationPath)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := trust.ParseKeyring(fixture.rootPublic)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := release.VerifyBinaryUpdateCurrent(receiptWire, delegationWire, roots,
		release.UpdateExpectation{Environment: "canary", Cell: "GRU", Architecture: "amd64"}, time.Now().UTC())
	if err != nil || verified.Receipt() != testBinaryReceipt() {
		t.Fatalf("auto-signed receipt does not verify: %v", err)
	}

	rejected := append([]string{}, args...)
	rejected[len(rejected)-1] = filepath.Join(fixture.directory, "rejected.json")
	notOnMain := func(_ context.Context, args ...string) error {
		if strings.Contains(strings.Join(args, " "), "origin/main") && strings.Contains(strings.Join(args, " "), "merge-base") {
			return errors.New("not an ancestor")
		}
		return nil
	}
	if err := c.signBinaryUpdateWith(rejected, check, inspect, notOnMain); !errors.Is(err, release.ErrLineage) {
		t.Fatalf("source outside main signed: %v", err)
	}
	if err := c.signBinaryUpdateWith(rejected, func(release.Qualification, string) error { return errors.New("run failed") }, inspect, git); err == nil {
		t.Fatal("unqualified run signed")
	}
	if _, err := os.Stat(rejected[len(rejected)-1]); !os.IsNotExist(err) {
		t.Fatal("rejected signing wrote a receipt")
	}
}
