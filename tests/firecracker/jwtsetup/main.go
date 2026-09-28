// Command jwtsetup creates private, one-run NATS operator and user JWT fixtures
// for the Firecracker qualification lab.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

const (
	maxBrokerCount = 3

	cellClaimMemoryBytes int64 = 128 << 20
	// JetStream reserves R3 MaxBytes once per replica. The bounded production
	// stores reserve 4.3125 GiB at R3; 6 GiB leaves headroom while each lab
	// broker's physical file store remains capped at 2 GiB.
	cellClaimDiskBytes int64 = 6 << 30
	cellClaimStreams         = 40
	cellClaimConsumers       = 40
)

type publicManifest struct {
	OperatorAccount string            `json:"operator_account"`
	SystemAccount   string            `json:"system_account"`
	CellAccount     string            `json:"cell_account"`
	Users           map[string]string `json:"users"`
}

type userGrants struct {
	publish      []string
	subscribe    []string
	responseMsgs int
	responseTTL  time.Duration
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "jwtsetup: %v\n", err)
		os.Exit(2)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("jwtsetup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("dir", "", "existing private per-run secrets directory")
	cell := flags.String("cell", "", "lowercase regional cell token")
	brokersText := flags.String("brokers", "", "comma-separated broker IDs")
	hostNode := flags.String("host-node", "", "host node identity")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	brokers, err := parseBrokers(*brokersText)
	if err != nil {
		return err
	}
	manifest, err := generateFixture(*directory, *cell, brokers, *hostNode)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("encode public identity manifest: %w", err)
	}
	if _, err := fmt.Fprintln(stdout, string(encoded)); err != nil {
		return fmt.Errorf("write public identity manifest: %w", err)
	}
	return nil
}

func parseBrokers(value string) ([]string, error) {
	if value == "" {
		return nil, errors.New("--brokers must name exactly three broker IDs")
	}
	brokers := strings.Split(value, ",")
	if len(brokers) != maxBrokerCount {
		return nil, errors.New("--brokers must name exactly three broker IDs")
	}
	seen := make(map[string]struct{}, len(brokers))
	for _, broker := range brokers {
		if !validToken(broker) {
			return nil, errors.New("--brokers contains an invalid broker ID")
		}
		if _, exists := seen[broker]; exists {
			return nil, errors.New("--brokers contains a duplicate broker ID")
		}
		seen[broker] = struct{}{}
	}
	return brokers, nil
}

func generateFixture(directory, cell string, brokers []string, hostNode string) (publicManifest, error) {
	if !validToken(cell) || !validToken(hostNode) || len(brokers) != maxBrokerCount {
		return publicManifest{}, errors.New("cell, host node, or broker set is invalid")
	}
	seen := make(map[string]struct{}, len(brokers))
	for _, broker := range brokers {
		if !validToken(broker) || broker == "host" || broker == "operator" || broker == "system" {
			return publicManifest{}, errors.New("broker ID is invalid")
		}
		if _, exists := seen[broker]; exists {
			return publicManifest{}, errors.New("broker IDs must be unique")
		}
		seen[broker] = struct{}{}
	}
	if err := validateSecretsDirectory(directory); err != nil {
		return publicManifest{}, err
	}
	names := outputNames(brokers)
	if err := rejectExistingOutputs(directory, names); err != nil {
		return publicManifest{}, err
	}
	manifest, files, err := makeFixtureFiles(cell, brokers, hostNode)
	if err != nil {
		return publicManifest{}, err
	}
	defer clearFiles(files)
	if err := writeFixtureFiles(directory, names, files); err != nil {
		return publicManifest{}, err
	}
	return manifest, nil
}

func validateSecretsDirectory(directory string) error {
	if directory == "" {
		return errors.New("--dir is required")
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect secrets directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("secrets directory must be a real directory with mode 0700")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return errors.New("secrets directory must be owned by the current user")
	}
	return nil
}

func rejectExistingOutputs(directory string, names []string) error {
	for _, name := range names {
		_, err := os.Lstat(filepath.Join(directory, name))
		if err == nil {
			return fmt.Errorf("output already exists: %s", name)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect output %s: %w", name, err)
		}
	}
	return nil
}

func outputNames(brokers []string) []string {
	names := []string{"operator.jwt", "system.jwt", "cell.jwt", "system.creds"}
	for _, broker := range brokers {
		names = append(names, broker+".creds")
	}
	return append(names, "host.creds", "operator.creds", "natsdiag.creds", "broker-ticket.key", "broker-ticket.pub")
}

func makeFixtureFiles(cell string, brokers []string, hostNode string) (publicManifest, map[string][]byte, error) {
	files := make(map[string][]byte, len(outputNames(brokers)))
	manifest, err := buildFixtureFiles(cell, brokers, hostNode, files)
	if err != nil {
		clearFiles(files)
		return publicManifest{}, nil, err
	}
	return manifest, files, nil
}

func buildFixtureFiles(cell string, brokers []string, hostNode string, files map[string][]byte) (publicManifest, error) {
	operatorKey, err := nkeys.CreateOperator()
	if err != nil {
		return publicManifest{}, fmt.Errorf("create operator account key: %w", err)
	}
	defer operatorKey.Wipe()
	systemKey, err := nkeys.CreateAccount()
	if err != nil {
		return publicManifest{}, fmt.Errorf("create system account key: %w", err)
	}
	defer systemKey.Wipe()
	cellKey, err := nkeys.CreateAccount()
	if err != nil {
		return publicManifest{}, fmt.Errorf("create cell account key: %w", err)
	}
	defer cellKey.Wipe()

	operatorID, err := operatorKey.PublicKey()
	if err != nil {
		return publicManifest{}, errors.New("read operator account public identity")
	}
	systemID, err := systemKey.PublicKey()
	if err != nil {
		return publicManifest{}, errors.New("read system account public identity")
	}
	cellID, err := cellKey.PublicKey()
	if err != nil {
		return publicManifest{}, errors.New("read cell account public identity")
	}

	operatorClaim := jwt.NewOperatorClaims(operatorID)
	operatorClaim.SystemAccount = systemID
	operatorJWT, err := operatorClaim.Encode(operatorKey)
	if err != nil {
		return publicManifest{}, fmt.Errorf("sign operator JWT: %w", err)
	}
	systemJWT, err := jwt.NewAccountClaims(systemID).Encode(operatorKey)
	if err != nil {
		return publicManifest{}, fmt.Errorf("sign system account JWT: %w", err)
	}
	cellClaim := jwt.NewAccountClaims(cellID)
	cellClaim.Limits.JetStreamLimits = jwt.JetStreamLimits{
		MemoryStorage: cellClaimMemoryBytes, DiskStorage: cellClaimDiskBytes,
		Streams: cellClaimStreams, Consumer: cellClaimConsumers,
	}
	cellJWT, err := cellClaim.Encode(operatorKey)
	if err != nil {
		return publicManifest{}, fmt.Errorf("sign cell account JWT: %w", err)
	}
	files["operator.jwt"] = []byte(operatorJWT + "\n")
	files["system.jwt"] = []byte(systemJWT + "\n")
	files["cell.jwt"] = []byte(cellJWT + "\n")

	manifest := publicManifest{
		OperatorAccount: operatorID, SystemAccount: systemID, CellAccount: cellID,
		Users: make(map[string]string, len(brokers)+4),
	}
	systemCredentials, systemUserID, err := makeCredentials(systemKey, systemID, func(public string) userGrants {
		return userGrants{
			publish:   []string{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"},
			subscribe: []string{inboxPrefix(cell, public) + ".>"},
		}
	})
	if err != nil {
		return publicManifest{}, fmt.Errorf("create in-process system credentials: %w", err)
	}
	files["system.creds"] = systemCredentials
	manifest.Users["system"] = systemUserID

	for _, broker := range brokers {
		credentials, public, err := makeCredentials(cellKey, cellID, func(public string) userGrants {
			publish, subscribe := controllerGrants(cell, broker, public)
			return userGrants{
				publish: publish, subscribe: subscribe, responseMsgs: 1, responseTTL: 5 * time.Second,
			}
		})
		if err != nil {
			return publicManifest{}, fmt.Errorf("create controller credentials for %s: %w", broker, err)
		}
		files[broker+".creds"] = credentials
		manifest.Users[broker] = public
	}

	hostCredentials, hostID, err := makeCredentials(cellKey, cellID, func(public string) userGrants {
		return userGrants{
			publish:   []string{hostObservationSubject(cell, hostNode)},
			subscribe: []string{inboxPrefix(cell, public) + ".>"},
		}
	})
	if err != nil {
		return publicManifest{}, fmt.Errorf("create host credentials: %w", err)
	}
	files["host.creds"] = hostCredentials
	manifest.Users["host"] = hostID

	operatorCredentials, operatorUserID, err := makeCredentials(cellKey, cellID, func(public string) userGrants {
		return userGrants{
			publish:   []string(natscell.BrokerOperatorPublishPermissions(cell)),
			subscribe: []string{inboxPrefix(cell, public) + ".>"},
		}
	})
	if err != nil {
		return publicManifest{}, fmt.Errorf("create operator credentials: %w", err)
	}
	files["operator.creds"] = operatorCredentials
	manifest.Users["operator"] = operatorUserID
	diagnosticCredentials, diagnosticUserID, err := makeCredentials(cellKey, cellID, func(public string) userGrants {
		return userGrants{
			publish:   diagnosticGrants(cell, hostNode),
			subscribe: []string{inboxPrefix(cell, public) + ".>"},
		}
	})
	if err != nil {
		return publicManifest{}, fmt.Errorf("create diagnostic credentials: %w", err)
	}
	files["natsdiag.creds"] = diagnosticCredentials
	manifest.Users["natsdiag"] = diagnosticUserID

	ticketPublic, ticketPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return publicManifest{}, fmt.Errorf("create broker ticket signing key: %w", err)
	}
	defer clear(ticketPrivate)
	files["broker-ticket.key"] = []byte(base64.StdEncoding.EncodeToString(ticketPrivate) + "\n")
	files["broker-ticket.pub"] = []byte(base64.StdEncoding.EncodeToString(ticketPublic) + "\n")
	return manifest, nil
}

func makeCredentials(accountKey nkeys.KeyPair, accountID string, grantsFor func(string) userGrants) ([]byte, string, error) {
	userKey, err := nkeys.CreateUser()
	if err != nil {
		return nil, "", fmt.Errorf("create NATS user key: %w", err)
	}
	defer userKey.Wipe()
	public, err := userKey.PublicKey()
	if err != nil {
		return nil, "", errors.New("read NATS user public identity")
	}
	grants := grantsFor(public)
	claim := jwt.NewUserClaims(public)
	claim.IssuerAccount = accountID
	claim.Pub.Allow = slices.Clone(grants.publish)
	claim.Sub.Allow = slices.Clone(grants.subscribe)
	if grants.responseMsgs != 0 || grants.responseTTL != 0 {
		claim.Resp = &jwt.ResponsePermission{MaxMsgs: grants.responseMsgs, Expires: grants.responseTTL}
	}
	raw, err := claim.Encode(accountKey)
	if err != nil {
		return nil, "", fmt.Errorf("sign NATS user JWT: %w", err)
	}
	seed, err := userKey.Seed()
	if err != nil {
		return nil, "", errors.New("read NATS user seed for decorated credentials")
	}
	defer clear(seed)
	credentials, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		return nil, "", errors.New("format decorated NATS user credentials")
	}
	return credentials, public, nil
}

func controllerGrants(cell, broker, public string) ([]string, []string) {
	root := "ts.orch.v1." + cell
	publish := []string{
		root + ".>", "ts.control." + cell + ".>", "$JS.API.>", "$KV.>", "$O.>",
		"$JS.ACK.TS_DELIVERY_INTENTS.TS_DELIVERY_WORKER.>",
		"ts.broker." + cell + ".ticket.>", "ts.broker." + cell + ".fence.>",
	}
	subscribe := []string{
		inboxPrefix(cell, public) + ".>",
		root + ".agent.*.observation.*", root + ".delivery.artifact.admit",
		root + ".host.register", root + ".placement.apply", root + ".broker.claim.apply",
		"ts.broker." + cell + ".ticket.>", "ts.broker." + cell + ".fence." + broker,
		root + ".terminal.>",
	}
	return publish, subscribe
}

func diagnosticGrants(cell, hostNode string) []string {
	return []string{
		"$JS.API.INFO",
		"$JS.API.STREAM.INFO.TS_DELIVERY_INTENTS", "$JS.API.STREAM.INFO.OBJ_TS_ARTIFACTS",
		"$JS.API.STREAM.INFO.KV_TS_DELIVERY_ADMISSIONS", "$JS.API.STREAM.INFO.KV_TS_DELIVERY_OPERATIONS",
		"$JS.API.STREAM.INFO.KV_TS_HOST_STATE", "$JS.API.STREAM.INFO.TS_CONTROL_LOG",
		"$JS.API.STREAM.MSG.GET.KV_TS_DELIVERY_OPERATIONS", "$JS.API.STREAM.MSG.GET.KV_TS_HOST_STATE",
		"$JS.API.STREAM.MSG.GET.TS_CONTROL_LOG",
		"$JS.API.DIRECT.GET.KV_TS_HOST_STATE.$KV.TS_HOST_STATE.session." + cell + "." + hostNode,
		"$JS.API.DIRECT.GET.KV_TS_HOST_STATE.$KV.TS_HOST_STATE.report." + cell + "." + hostNode + ".terrabase",
		"$JS.API.DIRECT.GET.KV_TS_DELIVERY_OPERATIONS.$KV.TS_DELIVERY_OPERATIONS.*",
	}
}

func hostObservationSubject(cell, node string) string {
	digest := sha256.Sum256([]byte(node))
	return "ts.orch.v1." + cell + ".agent." + hex.EncodeToString(digest[:]) + ".observation.*"
}

func inboxPrefix(cell, public string) string {
	return "ts.orch.v1." + cell + ".inbox." + public
}

func writeFixtureFiles(directory string, names []string, files map[string][]byte) (err error) {
	created := make([]string, 0, len(names))
	defer func() {
		if err == nil {
			return
		}
		for _, path := range created {
			_ = os.Remove(path)
		}
	}()
	for _, name := range names {
		contents, exists := files[name]
		if !exists {
			return fmt.Errorf("fixture output %s was not generated", name)
		}
		path := filepath.Join(directory, name)
		file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if openErr != nil {
			return fmt.Errorf("create fixture output %s: %w", name, openErr)
		}
		created = append(created, path)
		if chmodErr := file.Chmod(0o600); chmodErr != nil {
			_ = file.Close()
			return fmt.Errorf("secure fixture output %s: %w", name, chmodErr)
		}
		if _, writeErr := file.Write(contents); writeErr != nil {
			_ = file.Close()
			return fmt.Errorf("write fixture output %s: %w", name, writeErr)
		}
		if syncErr := file.Sync(); syncErr != nil {
			_ = file.Close()
			return fmt.Errorf("sync fixture output %s: %w", name, syncErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return fmt.Errorf("close fixture output %s: %w", name, closeErr)
		}
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open secrets directory for sync: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("sync secrets directory: %w", err)
	}
	return nil
}

func clearFiles(files map[string][]byte) {
	for _, contents := range files {
		clear(contents)
	}
}

func validToken(value string) bool {
	if value == "" || value[0] < 'a' || value[0] > 'z' || len(value) > 63 {
		return false
	}
	for _, character := range value[1:] {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
