package signedrelease

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/commandio"
)

const (
	assetAMD64 = "terrascale-orchestrator-linux-amd64"
	assetARM64 = "terrascale-orchestrator-linux-arm64"
	apiBase    = "https://api.github.com/repos/TerraScale/ts-orchestrator/releases"
)

func usageError() error {
	return errors.New("usage: ts-orch release <manifest|sign|verify> [flags]")
}

type command struct {
	ctx    context.Context
	output io.Writer
}

func Run(ctx context.Context, args []string, output io.Writer) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	writer := commandio.NewWriter(output)
	err = (command{ctx: ctx, output: writer}).run(args)
	return errors.Join(err, ctx.Err(), writer.Err())
}

func (c command) run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "manifest":
		return c.manifest(args[1:])
	case "sign":
		return c.sign(args[1:])
	case "verify":
		return c.verify(args[1:])
	default:
		return usageError()
	}
}

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	PublishedAt time.Time `json:"published_at"`
	Assets      []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func (c command) manifest(args []string) error {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	sha := flags.String("sha", "", "40-hex commit the CI release built")
	sequence := flags.Uint64("sequence", 0, "monotonic production release sequence")
	out := flags.String("out", "", "manifest output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *sha == "" || !shaPattern.MatchString(*sha) || *sequence == 0 || *out == "" || flags.NArg() != 0 {
		return errors.New("usage: ts-orch release manifest --sha SHA --sequence N --out FILE")
	}
	releases, err := c.listReleases()
	if err != nil {
		return err
	}
	prefix := "ci-" + *sha + "-run-"
	newest := -1
	for i, r := range releases {
		if strings.HasPrefix(r.TagName, prefix) && (newest < 0 || r.PublishedAt.After(releases[newest].PublishedAt)) {
			newest = i
		}
	}
	if newest < 0 {
		return fmt.Errorf("no CI release for %s", *sha)
	}
	binaries := map[string]Binary{}
	for _, osArch := range manifestArchs {
		name := assetAMD64
		if osArch == "linux/arm64" {
			name = assetARM64
		}
		url := ""
		for _, a := range releases[newest].Assets {
			if a.Name == name {
				url = a.BrowserDownloadURL
				break
			}
		}
		if url == "" {
			return fmt.Errorf("no CI release for %s: asset %s is missing", *sha, name)
		}
		if !strings.HasPrefix(url, downloadPrefix) {
			return fmt.Errorf("signedrelease: asset URL %q is not a ts-orchestrator release download", url)
		}
		digest, err := c.downloadSHA256(url)
		if err != nil {
			return err
		}
		binaries[osArch] = Binary{URL: url, SHA256: digest}
	}
	m := Manifest{
		V:        1,
		Channel:  "production",
		Sequence: *sequence,
		SHA:      *sha,
		Created:  time.Now().Unix(),
		Binaries: binaries,
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := os.WriteFile(*out, body, 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintln(c.output, *out)
	return err
}

func (c command) listReleases() ([]ghRelease, error) {
	var releases []ghRelease
	for page := 1; ; page++ {
		req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, fmt.Sprintf("%s?per_page=100&page=%d", apiBase, page), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		if token := os.Getenv("GITHUB_TOKEN"); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		var batch []ghRelease
		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("signedrelease: listing releases: %s", resp.Status)
		} else {
			err = json.NewDecoder(resp.Body).Decode(&batch)
		}
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		releases = append(releases, batch...)
		if !strings.Contains(resp.Header.Get("Link"), "rel=\"next\"") {
			return releases, nil
		}
	}
}

func (c command) downloadSHA256(url string) (string, error) {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("signedrelease: downloading %s: %s", url, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c command) sign(args []string) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifest := flags.String("manifest", "", "manifest file to sign")
	key := flags.String("key", "", "private key file for ssh-keygen -Y sign")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || *key == "" || flags.NArg() != 0 {
		return errors.New("usage: ts-orch release sign --manifest FILE --key KEYFILE")
	}
	if _, err := os.Stat(*manifest); err != nil {
		return err
	}
	cmd := exec.CommandContext(c.ctx, "ssh-keygen", "-Y", "sign", "-n", Namespace, "-f", *key, *manifest)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	sig := *manifest + ".sig"
	if _, err := os.Stat(sig); err != nil {
		return err
	}
	_, err := fmt.Fprintln(c.output, sig)
	return err
}

func (c command) verify(args []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifest := flags.String("manifest", "", "manifest file to verify")
	sig := flags.String("sig", "", "signature file (default MANIFEST.sig)")
	allowed := flags.String("allowed", "", "allowed-keys JSON file (default: the embedded list)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || flags.NArg() != 0 {
		return errors.New("usage: ts-orch release verify --manifest FILE [--sig FILE.sig] [--allowed FILE]")
	}
	sigPath := *sig
	if sigPath == "" {
		sigPath = *manifest + ".sig"
	}
	manifestBody, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	signature, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	var keys []AllowedKey
	if *allowed != "" {
		body, err := os.ReadFile(*allowed)
		if err != nil {
			return err
		}
		keys, err = parseAllowed(body)
		if err != nil {
			return err
		}
	} else {
		keys, err = Allowed()
		if err != nil {
			return err
		}
	}
	m, signer, err := verifyWith(manifestBody, signature, keys)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.output, "ok sequence=%d sha=%s signer=%s\n", m.Sequence, m.SHA, signer)
	return err
}
