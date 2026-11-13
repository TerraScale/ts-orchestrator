package releasepush

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const (
	healthWait   = 3 * time.Minute
	healthSteady = 15 * time.Second
	healthEvery  = 2 * time.Second
	versionProbe = 10 * time.Second
)

const pushUsage = "usage: ts-orch release push --sha <40 hex> --dir <dir with " + assetPrefix + "<arch>> [--regions deploy/m1/regions.json]"

// Region is one deploy/m1/regions.json entry; a new region is one more line.
type Region struct {
	Region string `json:"region"`
	NATS   string `json:"nats"`
	// SPKISHA256 pins the listener key: hex or base64 sha256 of its
	// SubjectPublicKeyInfo, printed on the host by `ts-orch release pin`.
	SPKISHA256 string `json:"spki_sha256"`
}

// Result is the one JSON line push prints per region.
type Result struct {
	Region      string        `json:"region"`
	State       string        `json:"state,omitempty"`
	ConnectMS   int64         `json:"connect_ms"`
	AcceptedMS  int64         `json:"accepted_ms"`
	ServingMS   int64         `json:"serving_ms"`
	ObservedAt  string        `json:"observed_at,omitempty"`
	StartedAt   string        `json:"started_at,omitempty"`
	HealthyMS   int64         `json:"healthy_ms"`
	Health      string        `json:"health,omitempty"`
	Workers     []HostVersion `json:"workers,omitempty"`
	Refusals    []HostVersion `json:"refusals,omitempty"`
	Unconfirmed string        `json:"unconfirmed,omitempty"`
	Error       string        `json:"error,omitempty"`
}

func Push(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release push", flag.ContinueOnError)
	flags.SetOutput(output)
	sha := flags.String("sha", "", "commit the release was built from")
	dir := flags.String("dir", "", "directory with the release binaries")
	regionsFile := flags.String("regions", "deploy/m1/regions.json", "region list")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !hex40.MatchString(*sha) || *dir == "" {
		return errors.New(pushUsage)
	}
	regions, err := LoadRegions(*regionsFile)
	if err != nil {
		return err
	}
	regions, err = pushOrder(regions)
	if err != nil {
		return err
	}
	token, err := MintToken(ctx)
	if err != nil {
		return err
	}
	run, err := tokenRunID(token)
	if err != nil {
		return err
	}
	release := OrchRelease{SHA: *sha, Binaries: map[string]Binary{}}
	for _, arch := range []string{"amd64", "arm64"} {
		sum, err := fileSHA256(filepath.Join(*dir, assetPrefix+arch))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		release.Binaries[arch] = Binary{URL: ReleaseURL(*sha, run, arch), SHA256: sum}
	}
	if len(release.Binaries) == 0 {
		return errors.New("no " + assetPrefix + "<arch> binary in " + *dir)
	}
	var failed error
	blocked := ""
	unconfirmed := map[string]string{}
	for _, region := range regions {
		note, err := dialPreflight(ctx, region)
		unconfirmed[region.Region] = note
		if err != nil {
			failed = fmt.Errorf("region %s preflight: %w", region.Region, err)
			blocked = region.Region
			break
		}
	}
	preflight := failed
	for index, region := range regions {
		result := Result{Region: region.Region}
		if blocked != "" {
			result.State, result.Error = "skipped", "not pushed: "+blocked+" failed"
			if preflight != nil && region.Region == blocked {
				result.State, result.Error = "failed", preflight.Error()
			}
		} else {
			release.Token, err = MintToken(ctx)
			if err == nil {
				result = pushRegion(ctx, region, release)
				if result.Error == "" && (result.State == "installed" || result.State == "current") {
					result.HealthyMS, result.Health, err = awaitHealthy(ctx, region, release)
				}
			}
			if err != nil {
				result.Error = err.Error()
			}
			if index == 0 && allPreflightRefused(result) {
				result.Error = "every host in the first region refused the same candidate preflight; rollout stopped"
			}
			if result.Error != "" {
				blocked = region.Region
				failed = errors.Join(failed, fmt.Errorf("region %s: %s", region.Region, result.Error))
			}
		}
		result.Unconfirmed = unconfirmed[region.Region]
		if refusal := RefusedOn(result.Refusals); refusal != "" {
			result.State = refusal
			failed = errors.Join(failed, fmt.Errorf("region %s: %s", region.Region, refusal))
		}
		line, _ := json.Marshal(result)
		if _, err := fmt.Fprintf(output, "%s\n", line); err != nil {
			return errors.Join(failed, err)
		}
	}
	return failed
}

func pushOrder(regions []Region) ([]Region, error) {
	names := catalog.Names()
	rank := make(map[string]int, len(names))
	for i, name := range names {
		rank[name] = i
	}
	rank[catalog.Founded()[0].Name()] = len(names)
	for _, region := range regions {
		if _, ok := rank[region.Region]; !ok {
			return nil, fmt.Errorf("unknown region %q", region.Region)
		}
	}
	ordered := slices.Clone(regions)
	slices.SortStableFunc(ordered, func(a, b Region) int { return cmp.Compare(rank[a.Region], rank[b.Region]) })
	return ordered, nil
}

func dialPreflight(ctx context.Context, region Region) (string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, versionProbe)
	defer cancel()
	token, err := MintToken(probeCtx)
	if err != nil {
		return "", err
	}
	deadline, _ := probeCtx.Deadline()
	if err := probeCtx.Err(); err != nil {
		return "", err
	}
	conn, err := Dial(region, token, nats.Timeout(time.Until(deadline)))
	if err != nil {
		return "", err
	}
	defer conn.Close()
	version, err := request(probeCtx, conn, SubjectVersion, nil, versionProbe)
	if err == nil && version.Version == "" {
		err = errors.New("empty version reply")
	}
	if err != nil {
		return "", err
	}
	note := ""
	if version.State == "unconfirmed" {
		note = version.Version + ": " + version.Error
	}
	health, err := request(ctx, conn, SubjectHealth, nil, healthRequestTimeout)
	if errors.Is(err, nats.ErrNoResponders) || (err == nil && health.Health == "no health check") {
		return note, nil
	}
	if err != nil {
		return note, fmt.Errorf("health: %w", err)
	}
	if health.Health != "ok" {
		return note, fmt.Errorf("health: %q", health.Health)
	}
	return note, nil
}

func awaitHealthy(ctx context.Context, region Region, release OrchRelease) (ms int64, last string, err error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, healthWait)
	defer cancel()
	token, err := MintToken(ctx)
	if err != nil {
		return 0, "", err
	}
	conn, err := Dial(region, token, nats.Name("ts-orch release health"))
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	tick := time.NewTicker(healthEvery)
	defer tick.Stop()
	var steady time.Time
	for {
		reply, probeErr := request(ctx, conn, SubjectHealth, nil, healthRequestTimeout)
		last = reply.Health
		if probeErr != nil {
			last = probeErr.Error()
		} else if reply.Version != release.SHA {
			last = fmt.Sprintf("health version %q, want %s", reply.Version, release.SHA)
		} else if last == "" {
			last = "empty health reply"
		}
		if last == "ok" && ctx.Err() == nil {
			if steady.IsZero() {
				steady = time.Now()
			}
			if time.Since(steady) >= healthSteady {
				return time.Since(start).Milliseconds(), last, nil
			}
		} else {
			steady = time.Time{}
		}
		select {
		case <-ctx.Done():
			return time.Since(start).Milliseconds(), last, fmt.Errorf("health of %s for %s: %w (last: %s)", region.Region, release.SHA, ctx.Err(), last)
		case <-tick.C:
		}
	}
}

// LoadRegions reads deploy/m1/regions.json.
func LoadRegions(path string) ([]Region, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var regions []Region
	if err := protocol.DecodeStrict(data, &regions, 64<<10); err != nil || len(regions) == 0 {
		return nil, fmt.Errorf("%s: %w", path, errors.Join(err, errors.New("needs at least one region")))
	}
	return regions, nil
}

// Dial opens a CI connection to region's pinned release listener; replies
// arrive on the token's run inbox.
func Dial(region Region, token string, options ...nats.Option) (*nats.Conn, error) {
	config, err := pinnedTLS(region.SPKISHA256)
	if err != nil {
		return nil, err
	}
	run, err := tokenRunID(token)
	if err != nil {
		return nil, err
	}
	conn, err := nats.Connect(region.NATS, append([]nats.Option{nats.Secure(config), nats.CustomInboxPrefix(Inbox(run)),
		nats.Token(token), nats.Timeout(10 * time.Second)}, options...)...)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return conn, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// MintToken requests a GitHub Actions OIDC token for the ts-orch audience.
func MintToken(ctx context.Context) (string, error) {
	endpoint, bearer := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if endpoint == "" || bearer == "" {
		return "", errors.New("GitHub OIDC is unavailable; the job needs permissions: id-token: write")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"&audience="+url.QueryEscape(Audience), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "bearer "+bearer)
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var body struct {
		Value string `json:"value"`
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mint OIDC token: %s", response.Status)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxTokenSize)).Decode(&body); err != nil || body.Value == "" {
		return "", errors.Join(errors.New("mint OIDC token: empty response"), err)
	}
	return body.Value, nil
}

func pushRegion(ctx context.Context, region Region, release OrchRelease) Result {
	start := time.Now()
	result := Result{Region: region.Region, StartedAt: start.UTC().Format(time.RFC3339Nano)}
	since := func() int64 { return time.Since(start).Milliseconds() }
	fail := func(err error) Result { result.Error = err.Error(); return result }
	conn, err := Dial(region, release.Token, nats.Name("ts-orch release push"),
		// The host restarts mid-push; reconnect immediately and keep trying.
		nats.MaxReconnects(-1), nats.ReconnectWait(250*time.Millisecond), nats.ReconnectJitter(0, 0))
	if err != nil {
		return fail(err)
	}
	defer conn.Close()
	result.ConnectMS = since()
	payload, err := json.Marshal(release)
	if err != nil {
		return fail(err)
	}
	reply, err := request(ctx, conn, SubjectOrch, payload, 2*time.Minute+WorkerReplyWait)
	if err != nil {
		return fail(fmt.Errorf("release: %w", err))
	}
	result.State, result.AcceptedMS = reply.State, since()
	result.Workers = reply.Workers
	for _, row := range reply.Workers {
		if row.Refusal != nil {
			if row.Refusal.Kind != RefusalHost {
				result.Error = "release integrity failure on " + row.Host + ": " + row.Refusal.Reason
			}
			result.Refusals = append(result.Refusals, row)
		}
	}
	if reply.Refusal != nil && reply.Refusal.SHA == release.SHA {
		host := reply.Host
		if host == "" {
			host = region.Region + " first host"
		}
		result.Refusals = append(result.Refusals, HostVersion{Host: host, Refusal: reply.Refusal})
		if reply.Refusal.Kind != RefusalHost {
			result.Error = "release integrity failure on " + host + ": " + reply.Refusal.Reason
		}
		return result
	}
	if result.Error != "" {
		return result
	}
	if reply.State != "installed" && reply.State != "current" {
		return fail(fmt.Errorf("release %s: %s", reply.State, reply.Error))
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		version, err := request(ctx, conn, SubjectVersion, nil, time.Second)
		if err == nil && version.Version == release.SHA && version.State == "unconfirmed" {
			result.State = "unconfirmed"
			return fail(errors.New("release remains unconfirmed: " + version.Error))
		}
		if err == nil && version.Version == release.SHA && version.State != "probation" {
			result.ServingMS = since()
			result.ObservedAt = time.Now().UTC().Format(time.RFC3339Nano)
			return result
		}
		if err == nil && version.RolledBack == release.SHA {
			result.State = "rolled_back"
			return fail(fmt.Errorf("the region rolled back to %s: %s", version.Version, version.Error))
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fail(errors.New("timed out waiting for the region to serve " + release.SHA))
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// pinnedTLS trusts exactly the listener key the region pins. The listener
// certificate is self-signed for no host name, so the pin replaces chain and
// name verification (InsecureSkipVerify only disables those; the pin check in
// VerifyPeerCertificate always runs).
func pinnedTLS(pin string) (*tls.Config, error) {
	want, err := hex.DecodeString(pin)
	if err != nil {
		want, err = base64.StdEncoding.DecodeString(pin)
	}
	if err != nil || len(want) != sha256.Size {
		return nil, errors.New("region has no valid spki_sha256 pin; run `ts-orch release pin` on its host and add it to deploy/m1/regions.json")
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // replaced by the SPKI pin below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("listener sent no certificate")
			}
			certificate, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			if sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo); subtle.ConstantTimeCompare(sum[:], want) != 1 {
				return errors.New("listener key does not match the region's spki_sha256 pin")
			}
			return nil
		},
	}, nil
}

// tokenRunID reads the run_id claim without verifying (the host verifies);
// it names this run's release and reply inbox.
func tokenRunID(token string) (string, error) {
	parts := strings.Split(token, ".")
	var claims Claims
	if len(parts) != 3 || decodeSegment(parts[1], &claims) != nil || !runID.MatchString(claims.RunID) {
		return "", errors.New("OIDC token has no run_id")
	}
	return claims.RunID, nil
}

func request(ctx context.Context, conn *nats.Conn, subject string, payload []byte, timeout time.Duration) (Reply, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	message, err := conn.RequestWithContext(ctx, subject, payload)
	if err != nil {
		return Reply{}, err
	}
	var reply Reply
	return reply, json.Unmarshal(message.Data, &reply)
}

func allPreflightRefused(result Result) bool {
	if len(result.Refusals) == 0 || len(result.Refusals) != len(result.Workers)+1 {
		return false
	}
	revision := ""
	for _, host := range result.Refusals {
		record := host.Refusal
		if record == nil || record.Kind != RefusalHost || !record.Preflight || record.Reason == "" || record.SHA == "" {
			return false
		}
		if revision == "" {
			revision = record.SHA
		} else if record.SHA != revision {
			return false
		}
	}
	return true
}
