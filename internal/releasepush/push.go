package releasepush

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
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
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

const pushUsage = "usage: ts-orch release push --sha <40 hex> --tag <release tag> --dir <dir with " + assetPrefix + "<arch>> [--regions deploy/m1/regions.json]"

// Region is one deploy/m1/regions.json entry; a new region is one more line.
type Region struct {
	Region string `json:"region"`
	NATS   string `json:"nats"`
}

// Result is the one JSON line push prints per region.
type Result struct {
	Region     string `json:"region"`
	State      string `json:"state,omitempty"`
	ConnectMS  int64  `json:"connect_ms"`
	AcceptedMS int64  `json:"accepted_ms"`
	ServingMS  int64  `json:"serving_ms"`
	Error      string `json:"error,omitempty"`
}

// Push sends a ts-orch release to every region concurrently and waits until
// each serves it. It runs in GitHub Actions with id-token: write.
func Push(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release push", flag.ContinueOnError)
	flags.SetOutput(output)
	sha := flags.String("sha", "", "commit the release was built from")
	tag := flags.String("tag", "", "GitHub release tag holding the binaries")
	dir := flags.String("dir", "", "directory with the release binaries")
	regionsFile := flags.String("regions", "deploy/m1/regions.json", "region list")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !hex40.MatchString(*sha) || !tagName.MatchString(*tag) || *dir == "" {
		return errors.New(pushUsage)
	}
	data, err := os.ReadFile(*regionsFile)
	if err != nil {
		return err
	}
	var regions []Region
	if err := protocol.DecodeStrict(data, &regions, 64<<10); err != nil || len(regions) == 0 {
		return fmt.Errorf("%s: %w", *regionsFile, errors.Join(err, errors.New("needs at least one region")))
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
		release.Binaries[arch] = Binary{URL: downloadPrefix + *tag + "/" + assetPrefix + arch, SHA256: sum}
	}
	if len(release.Binaries) == 0 {
		return errors.New("no " + assetPrefix + "<arch> binary in " + *dir)
	}
	if release.Token, err = MintToken(ctx); err != nil {
		return err
	}
	results := make([]Result, len(regions))
	var wg sync.WaitGroup
	for i, region := range regions {
		wg.Go(func() { results[i] = pushRegion(ctx, region, release) })
	}
	wg.Wait()
	var failed error
	for _, result := range results {
		line, _ := json.Marshal(result)
		if _, err := fmt.Fprintf(output, "%s\n", line); err != nil {
			return err
		}
		if result.Error != "" {
			failed = errors.Join(failed, fmt.Errorf("region %s: %s", result.Region, result.Error))
		}
	}
	return failed
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

// pushRegion never returns early for another region's failure.
func pushRegion(ctx context.Context, region Region, release OrchRelease) Result {
	result := Result{Region: region.Region}
	start := time.Now()
	since := func() int64 { return time.Since(start).Milliseconds() }
	fail := func(err error) Result { result.Error = err.Error(); return result }
	conn, err := nats.Connect(region.NATS,
		// shortcut: the listener certificate is self-signed, so CI skips
		// verification; integrity is the OIDC signature on the message.
		// Pin or use an ACME certificate when another client needs trust.
		nats.Secure(&tls.Config{InsecureSkipVerify: true}), //nolint:gosec // see shortcut above
		nats.Token(release.Token), nats.Name("ts-orch release push"), nats.Timeout(10*time.Second),
		// The host restarts mid-push; reconnect immediately and keep trying.
		nats.MaxReconnects(-1), nats.ReconnectWait(250*time.Millisecond), nats.ReconnectJitter(0, 0))
	if err != nil {
		return fail(fmt.Errorf("connect: %w", err))
	}
	defer conn.Close()
	result.ConnectMS = since()
	payload, err := json.Marshal(release)
	if err != nil {
		return fail(err)
	}
	reply, err := request(ctx, conn, SubjectOrch, payload, 2*time.Minute)
	if err != nil {
		return fail(fmt.Errorf("release: %w", err))
	}
	result.State, result.AcceptedMS = reply.State, since()
	if reply.State != "installed" && reply.State != "current" {
		return fail(fmt.Errorf("release %s: %s", reply.State, reply.Error))
	}
	deadline := time.Now().Add(3 * time.Minute)
	for {
		if version, err := request(ctx, conn, SubjectVersion, nil, time.Second); err == nil && version.Version == release.SHA {
			result.ServingMS = since()
			return result
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
