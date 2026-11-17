package regionhost

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const (
	repo        = "TerraScale/ts-orchestrator"
	regionsFile = "deploy/m1/regions.json"
)

func (r *run) publicIP(inst *core.Instance) (string, error) {
	attachments, err := r.compute.ListVnicAttachments(r.ctx, core.ListVnicAttachmentsRequest{CompartmentId: &r.compartment, InstanceId: inst.Id})
	if err != nil {
		return "", err
	}
	for _, a := range attachments.Items {
		if a.LifecycleState != core.VnicAttachmentLifecycleStateAttached {
			continue
		}
		v, err := r.net.GetVnic(r.ctx, core.GetVnicRequest{VnicId: a.VnicId})
		if err != nil {
			return "", err
		}
		if deref(v.IsPrimary) && deref(v.PublicIp) != "" {
			return *v.PublicIp, nil
		}
	}
	return "", fmt.Errorf("instance %s has no public IP", deref(inst.DisplayName))
}

func (r *run) ensureDNS(ip string) error {
	token := os.Getenv(publicapi.TokenEnv)
	if token == "" {
		token = os.Getenv("CLOUDFLARE_API_TOKEN") // the cf CLI's login on the operator hosts
	}
	if token == "" {
		return errors.New("a Cloudflare DNS token is required in " + publicapi.TokenEnv)
	}
	name := r.code + ".mesh." + publicapi.Zone
	verb, id, err := publicapi.Cloudflare{Token: token}.DNSOnlyA(r.ctx, name, ip, r.dry)
	if err != nil {
		return err
	}
	return r.report(verb, "dns", name, id)
}

func withRegion(regions []releasepush.Region, want releasepush.Region, remove bool) ([]releasepush.Region, bool) {
	i := slices.IndexFunc(regions, func(r releasepush.Region) bool { return r.Region == want.Region })
	switch {
	case i < 0 && remove:
		return regions, false
	case i < 0:
		return append(slices.Clone(regions), want), true
	case remove:
		return slices.Delete(slices.Clone(regions), i, i+1), true
	case regions[i] == want:
		return regions, false
	}
	next := slices.Clone(regions)
	next[i] = want
	return next, true
}

func formatRegions(regions []releasepush.Region) []byte {
	lines := make([]string, len(regions))
	for i, r := range regions {
		lines[i] = fmt.Sprintf(`  {"region": %q}`, r.Region)
	}
	return []byte("[\n" + strings.Join(lines, ",\n") + "\n]\n")
}

func (r *run) ensureObservationRegion(remove bool) error {
	regions, err := releasepush.LoadRegions(regionsFile)
	if err != nil {
		return fmt.Errorf("run from the repository root: %w", err)
	}
	want := releasepush.Region{Region: r.code}
	if _, changed := withRegion(regions, want, remove); !changed {
		return r.report("unchanged", "observer-region", r.code, want.Region)
	}
	verb := "updated"
	if remove {
		verb = "deleted"
	}
	if r.dry {
		return r.report(verb, "observer-region", r.code, want.Region)
	}
	url, err := r.regionPR(want, remove)
	if err != nil {
		return err
	}
	return r.report(verb, "observer-region", r.code, url)
}

func (r *run) regionPR(want releasepush.Region, remove bool) (string, error) {
	branch := "region-" + r.code + "-observer"
	head, err := gh(r.ctx, "api", "repos/"+repo+"/git/ref/heads/main", "--jq", ".object.sha")
	if err != nil {
		return "", err
	}
	var file struct{ Content, SHA string }
	data, err := gh(r.ctx, "api", "repos/"+repo+"/contents/"+regionsFile+"?ref="+head)
	if err == nil {
		err = json.Unmarshal([]byte(data), &file, json.MatchCaseInsensitiveNames(true))
	}
	if err != nil {
		return "", err
	}
	current, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
	var regions []releasepush.Region
	if err == nil {
		err = json.Unmarshal(current, &regions)
	}
	if err != nil {
		return "", err
	}
	next, changed := withRegion(regions, want, remove)
	if !changed {
		return "main", nil // already merged; the local checkout is behind
	}
	if _, err := gh(r.ctx, "api", "-X", "POST", "repos/"+repo+"/git/refs", "-f", "ref=refs/heads/"+branch, "-f", "sha="+head); err != nil {
		if _, err := gh(r.ctx, "api", "-X", "PATCH", "repos/"+repo+"/git/refs/heads/"+branch, "-f", "sha="+head, "-F", "force=true"); err != nil {
			return "", err
		}
	}
	title := "chore(m1): " + r.code + " HTTPS observer region in regions.json"
	if _, err := gh(r.ctx, "api", "-X", "PUT", "repos/"+repo+"/contents/"+regionsFile, "-f", "message="+title, "-f", "branch="+branch,
		"-f", "sha="+file.SHA, "-f", "content="+base64.StdEncoding.EncodeToString(formatRegions(next))); err != nil {
		return "", err
	}
	url, err := gh(r.ctx, "pr", "create", "--repo", repo, "--base", "main", "--head", branch, "--title", title,
		"--body", "`ts-orch region add|rm "+r.code+"`: the region's HTTPS observer membership differs from regions.json.")
	if err != nil {
		if url, err = gh(r.ctx, "pr", "view", branch, "--repo", repo, "--json", "url", "--jq", ".url"); err != nil {
			return "", err
		}
	}
	_, err = gh(r.ctx, "pr", "merge", branch, "--repo", repo, "--auto", "--squash")
	return url, err
}

func gh(ctx context.Context, args ...string) (string, error) {
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "gh", args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gh %s: %w: %s", args[0], err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}
