package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type stringList []string

func (list *stringList) String() string { return strings.Join(*list, ",") }
func (list *stringList) Set(value string) error {
	if slices.Contains(*list, value) {
		return fmt.Errorf("duplicate value %q", value)
	}
	*list = append(*list, value)
	return nil
}

// serviceList is the repeatable --service ROLE=REPOSITORY flag.
type serviceList []release.ServiceGrant

func (list *serviceList) String() string { return fmt.Sprint(*list) }
func (list *serviceList) Set(value string) error {
	role, repository, ok := strings.Cut(value, "=")
	if !ok || role == "" || repository == "" {
		return fmt.Errorf("service %q must be ROLE=REPOSITORY", value)
	}
	*list = append(*list, release.ServiceGrant{Role: role, Repository: repository})
	return nil
}

// signUpdateDelegation is the offline root operation that issues a scoped,
// time-bounded binary update delegation to one online leaf key.
func (c command) signUpdateDelegation(args []string) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	flags := flag.NewFlagSet("sign-update-delegation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	leafPath := flags.String("subject-public-key", "", "online leaf Ed25519 PKIX public key PEM")
	rootPath := flags.String("root-key", "", "offline root Ed25519 PKIX public key PEM")
	privatePath := flags.String("signing-key", "", "owner-only offline root Ed25519 PKCS#8 private key PEM")
	environment := flags.String("environment", "", "production or canary")
	lineageBase := flags.String("lineage-base", "", "reviewed main revision every signed source must descend from")
	var services serviceList
	var architectures stringList
	flags.Var(&services, "service", "service role and repository ROLE=REPOSITORY the leaf may release; repeatable")
	flags.Var(&architectures, "arch", "amd64 or arm64; repeatable")
	issuedAtText := flags.String("issued-at", "", "canonical UTC RFC3339 issuance instant")
	expiresAtText := flags.String("expires-at", "", "canonical UTC RFC3339 expiry instant")
	output := flags.String("out", "", "new root-signed binary update delegation")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *leafPath == "" || *rootPath == "" || *privatePath == "" || *output == "" || flags.NArg() != 0 ||
		!validEnvironment(*environment) || !release.ValidSourceRevision(*lineageBase) || len(architectures) == 0 {
		return errors.New("sign-update-delegation requires keys, --environment, --lineage-base, --arch, a UTC interval and --out; --service is repeatable")
	}
	issuedAt, err := parseDelegationUTC(*issuedAtText)
	if err != nil {
		return fmt.Errorf("issued-at: %w", err)
	}
	expiresAt, err := parseDelegationUTC(*expiresAtText)
	if err != nil {
		return fmt.Errorf("expires-at: %w", err)
	}
	leafPublic, err := readLeafPublicKey(*leafPath)
	if err != nil {
		return err
	}
	rootPublic, err := readRootPublicKey(*rootPath)
	if err != nil {
		return err
	}
	// Keep the offline-root/online-leaf separation: this grant authorizes
	// automatic signing, so delegating it to the root itself would invite
	// putting the root private key online.
	if bytes.Equal(leafPublic, rootPublic) {
		return errors.New("delegated update leaf must differ from offline root")
	}
	rootPrivate, err := readOfflineRootPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(rootPrivate)
	if !bytes.Equal(rootPrivate.Public().(ed25519.PublicKey), rootPublic) {
		return errors.New("offline root signing key does not match root public key")
	}
	leafID, err := trust.KeyID(leafPublic)
	if err != nil {
		return err
	}
	leafEncoded, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		return err
	}
	slices.Sort(architectures)
	slices.SortFunc(services, func(a, b release.ServiceGrant) int { return strings.Compare(a.Role, b.Role) })
	delegation := release.BinaryUpdateDelegation{
		Schema: release.UpdateDelegationSchema, SubjectKeyID: leafID, SubjectPublicKey: leafEncoded,
		Environment: *environment, Architectures: architectures, Services: services,
		Repository: release.QualificationRepository, Workflow: release.QualificationWorkflow,
		Ref: release.LineageRef, LineageBase: *lineageBase,
	}
	envelope, err := release.SignUpdateDelegation(delegation, issuedAt, expiresAt, rootPrivate)
	if err != nil {
		return err
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	return c.writeNew(*output, wire, 0o644)
}

// gitLineage proves ancestry in a verified checkout of the repository after
// fetching main without force: the source must descend from the delegation's
// base and be contained in origin/main. origin must resolve to the pinned
// repository on the pinned GitHub host, so a fork or a repointed remote can
// never stand in for reviewed main.
type gitLineage struct {
	ctx      context.Context
	checkout string
	run      func(ctx context.Context, args ...string) (string, error)
}

// lineageHost is the GitHub host that serves release.QualificationRepository.
const lineageHost = "github.com"

func runGit(ctx context.Context, args ...string) (string, error) {
	command := exec.CommandContext(ctx, "git", args...)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return string(output), nil
}

// pinnedLineageRemote reports whether a git remote URL (after insteadOf
// rewriting, as `git remote get-url` reports it) names the pinned repository
// on the pinned host over https or ssh.
func pinnedLineageRemote(raw string) bool {
	raw = strings.TrimSpace(raw)
	var host, path string
	if rest, ok := strings.CutPrefix(raw, "git@"); ok && !strings.Contains(raw, "://") {
		host, path, ok = strings.Cut(rest, ":")
		if !ok {
			return false
		}
	} else {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Opaque != "" {
			return false
		}
		switch parsed.Scheme {
		case "https":
			if parsed.User != nil || parsed.Port() != "" {
				return false
			}
		case "ssh":
			if parsed.User == nil || parsed.User.Username() != "git" {
				return false
			}
			if _, hasPassword := parsed.User.Password(); hasPassword {
				return false
			}
		default:
			return false
		}
		host, path = parsed.Hostname(), parsed.Path
	}
	path = strings.TrimSuffix(strings.TrimPrefix(path, "/"), ".git")
	return host == lineageHost && path == release.QualificationRepository
}

func (lineage gitLineage) CheckLineage(base, revision, ref string) error {
	if ref != release.LineageRef || !release.ValidSourceRevision(base) || !release.ValidSourceRevision(revision) {
		return errors.New("unsupported lineage request")
	}
	ctx, cancel := context.WithTimeout(lineage.ctx, 2*time.Minute)
	defer cancel()
	origin, err := lineage.run(ctx, "-C", lineage.checkout, "remote", "get-url", "origin")
	if err != nil {
		return err
	}
	if !pinnedLineageRemote(origin) {
		return fmt.Errorf("lineage checkout origin %q is not %s/%s", strings.TrimSpace(origin), lineageHost, release.QualificationRepository)
	}
	if _, err := lineage.run(ctx, "-C", lineage.checkout, "fetch", "--quiet", "--no-tags", "origin",
		"refs/heads/main:refs/remotes/origin/main"); err != nil {
		return err
	}
	if _, err := lineage.run(ctx, "-C", lineage.checkout, "merge-base", "--is-ancestor", base, revision); err != nil {
		return fmt.Errorf("source does not descend from the lineage base: %w", err)
	}
	if _, err := lineage.run(ctx, "-C", lineage.checkout, "merge-base", "--is-ancestor", revision, "refs/remotes/origin/main"); err != nil {
		return fmt.Errorf("source is not on main: %w", err)
	}
	return nil
}

func (c command) signBinaryUpdate(args []string) error {
	return c.signBinaryUpdateWith(args, c.verifyGitHubQualification, c.inspectBinary, runGit)
}

// signBinaryUpdateWith is the online leaf operation: it applies every check
// of sign-binary (candidate, exact retained binary, successful GitHub
// qualification run), proves lineage, and signs an update receipt under the
// scoped delegation.
func (c command) signBinaryUpdateWith(args []string, check func(release.Qualification, string) error,
	inspect func(string, string, string) (binaryReceipt, error), git func(context.Context, ...string) (string, error),
) error {
	flags := flag.NewFlagSet("sign-binary-update", flag.ContinueOnError)
	evidenceDir := flags.String("production-evidence-dir", "", "retained signed runtime and workload evidence; default qualification directory/production")
	flags.SetOutput(io.Discard)
	candidate := flags.String("candidate", "", "unsigned canonical binary receipt")
	binaryPath := flags.String("binary", "", "retained CI binary matching the candidate")
	qualificationPath := flags.String("qualification", "", "retained CI qualification manifest")
	delegationPath := flags.String("update-delegation", "", "root-signed binary update delegation")
	rootPath := flags.String("root-key", "", "baked root public key PEM")
	privatePath := flags.String("signing-key", "", "delegated Ed25519 PKCS#8 private key PEM")
	environment := flags.String("environment", "", "production or canary")
	cell := flags.String("cell", "", "logical cell GRU, SFO or FRA")
	checkout := flags.String("source-checkout", "", "repository checkout used to prove lineage")
	validFor := flags.Duration("valid-for", 7*24*time.Hour, "receipt validity, bounded by delegation expiry")
	output := flags.String("out", "", "new signed update receipt path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidate == "" || *binaryPath == "" || *qualificationPath == "" || *delegationPath == "" || *rootPath == "" ||
		*privatePath == "" || !validEnvironment(*environment) || !validRegion(*cell) || *checkout == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("sign-binary-update requires --candidate, --binary, --qualification, --update-delegation, --root-key, --signing-key, --environment, --cell, --source-checkout and --out")
	}
	payload, err := readCanonicalPayload[binaryReceipt](*candidate)
	if err != nil {
		return err
	}
	qualification, qualificationDigest, err := readQualification(*qualificationPath)
	if err != nil {
		return err
	}
	if err := qualification.MatchBinary(payload, qualificationDigest); err != nil {
		return err
	}
	observed, err := inspect(*binaryPath, payload.GoVersion, payload.SourceRevision)
	if err != nil {
		return err
	}
	observed.QualificationSHA256 = qualificationDigest
	if observed != payload {
		return errors.New("retained CI binary does not match the qualified candidate")
	}
	if err := check(qualification, qualificationDigest); err != nil {
		return err
	}
	delegation, err := readEnvelope(*delegationPath)
	if err != nil {
		return err
	}
	root, err := readRootPublicKey(*rootPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		return err
	}
	if *evidenceDir == "" {
		*evidenceDir = filepath.Join(filepath.Dir(*qualificationPath), "production")
	}
	if err := c.verifyProductionArtifacts(*evidenceDir, roots, *cell, *environment, map[string]binaryReceipt{payload.GOARCH: payload}, time.Now().UTC()); err != nil {
		return err
	}
	proof, err := readProductionProof(*evidenceDir, *cell, payload.GOARCH)
	if err != nil {
		return err
	}
	private, err := readDelegatedPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(private)
	envelope, err := release.SignBinaryUpdateReceipt(payload, qualification, qualificationDigest, *cell, *environment,
		gitLineage{ctx: c.ctx, checkout: *checkout, run: git}, delegation, roots, private, time.Now().UTC(), *validFor)
	if err != nil {
		return err
	}
	delegationWire, err := trust.EncodeEnvelope(delegation)
	if err != nil {
		return err
	}
	envelope, err = release.AttachProductionQualification(envelope, proof, delegationWire, roots, private,
		release.UpdateExpectation{Environment: *environment, Cell: *cell, Architecture: payload.GOARCH}, time.Now().UTC())
	if err != nil {
		return err
	}
	encoded, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	if err := c.writeNew(*output, encoded, 0o644); err != nil {
		return err
	}
	// The receipt never outlives its delegation; report the effective
	// expiry so a shortened receipt is visible.
	fmt.Fprintf(c.output, "update receipt valid until %s\n", envelope.ExpiresAt.UTC().Format(time.RFC3339))
	return nil
}
