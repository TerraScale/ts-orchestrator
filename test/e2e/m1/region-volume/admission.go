package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	document "github.com/TerraScale/ts-orchestrator/deploy/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/pullrelease"
	"github.com/TerraScale/ts-orchestrator/internal/regionhost"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasegate"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/oraclehost"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/sigstore"
)

var admittedExecutable string
var admittedTag string
var admittedDigest string
var releaseResponses map[string][]byte

func prepareRelease(dir string) error {
	authority := sigstore.New()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		return err
	}
	binary, err = sigstore.TrustBinary(binary, authority.TrustedRoot())
	if err != nil {
		return err
	}
	admittedExecutable = filepath.Join(dir, "region-volume-admitted")
	if err := os.WriteFile(admittedExecutable, oraclehost.StagingSigned(binary), 0700); err != nil {
		return err
	}
	sha, run := "1111111111111111111111111111111111111111", "123"
	tag := releaseattest.Tag(sha, run)
	asset := releaseattest.AssetPrefix + "arm64"
	payload := []byte("region volume journey release")
	digest := sha256.Sum256(payload)
	admittedTag, admittedDigest = tag, hex.EncodeToString(digest[:])
	now := time.Now().UTC()
	record, err := json.Marshal(releasegate.StagingRecord{
		Binaries: map[string]string{"arm64": hex.EncodeToString(digest[:])}, BakeFor: pullrelease.DefaultBakeFor,
		Region: fleet.Embedded().Staging.Label, Tag: tag, Done: now.Add(-2 * pullrelease.DefaultBakeFor),
		Baked: now.Add(-pullrelease.DefaultBakeFor), Signed: now,
	})
	if err != nil {
		return err
	}
	signed, err := oraclehost.SignStaging(record)
	if err != nil {
		return err
	}
	completion, err := json.Marshal(signed)
	if err != nil {
		return err
	}
	releases, err := json.Marshal([]object{{"tag_name": tag, "assets": []object{{"name": asset}, {"name": releaseattest.BundleAsset}}}})
	if err != nil {
		return err
	}
	releaseResponses = map[string][]byte{
		"api.github.com/repos/" + releaseattest.Repository + "/releases?per_page=30":                             releases,
		"github.com/" + releaseattest.Repository + "/releases/download/" + tag + "/" + releaseattest.BundleAsset: authority.Bundle(sigstore.MainIdentity, sha, run, map[string][]byte{asset: payload}),
		"raw.githubusercontent.com/" + releaseattest.Repository + "/" + sha + "/deploy/fleet/fleet.json":         document.Document,
	}
	gate, err := url.Parse(fleet.Embedded().Staging.GateURL(tag))
	if err != nil {
		return err
	}
	releaseResponses[gate.Host+gate.RequestURI()] = completion
	releaseResponses[gate.Host+gate.RequestURI()+releasegate.WithdrawalSuffix] = nil
	return nil
}

func serveRelease(w http.ResponseWriter, r *http.Request) bool {
	data, ok := releaseResponses[r.Host+r.URL.RequestURI()]
	if !ok {
		return false
	}
	if data == nil {
		http.NotFound(w, r)
		return true
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
	return true
}

func regionCommand(address string, args []string) error {
	transport := &http.Transport{DialTLSContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}}
	http.DefaultTransport = transport
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	return regionhost.Run(ctx, args, os.Stdout)
}
