package pullrelease

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const (
	stagingFresh   = 3 * DefaultPoll
	stagingMaxSize = 64 << 10

	GateMissing    = "missing"
	GateUnreadable = "unreadable"
	GateUnsigned   = "unsigned"
	GateBaking     = "baking"
	GateStale      = "stale"
	GateLatency    = "latency"

	LatencyAsset = "staging-latency.json"
	LatencyPass  = "pass"
	LatencyFail  = "fail"
)

type LatencyVerdict struct {
	Verdict string `json:"verdict"`
	Run     string `json:"run"`
}

func (v LatencyVerdict) validate() error {
	if v.Verdict != LatencyPass && v.Verdict != LatencyFail {
		return fmt.Errorf("latency verdict %q is not %s or %s", v.Verdict, LatencyPass, LatencyFail)
	}
	if !strings.HasPrefix(v.Run, "https://") {
		return fmt.Errorf("latency verdict run %q is not an https URL", v.Run)
	}
	return nil
}

type StagingRecord struct {
	Region  string         `json:"region"`
	Tag     string         `json:"tag"`
	Done    time.Time      `json:"done"`
	Baked   time.Time      `json:"baked"`
	Signed  time.Time      `json:"signed"`
	Latency LatencyVerdict `json:"latency"`
}

type SignedRecord struct {
	Record    []byte `json:"record"`
	Signature []byte `json:"signature"`
}

type gateBlock struct {
	region string
	tag    string
	code   string
	since  time.Time
}

var stagingBlock atomic.Pointer[gateBlock]

func (u *Updater) publishStaging(ctx context.Context) error {
	staging := fleet.Embedded().Staging
	latency, err := u.latency(ctx)
	if err != nil {
		return err
	}
	record, err := json.Marshal(StagingRecord{Region: u.Region, Tag: u.status.Target.Tag(), Done: u.status.Done, Baked: u.status.Passed, Signed: time.Now().UTC(), Latency: latency})
	if err != nil {
		return err
	}
	factory, err := ociclient.InstancePrincipalContext(ctx, staging.OCIRegion)
	if err != nil {
		return err
	}
	vaults, err := keymanagement.NewKmsVaultClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return err
	}
	vaults.SetRegion(factory.Region())
	factory.Configure(&vaults.BaseClient, ociclient.ServiceKMS)
	vault, err := vaults.GetVault(ctx, keymanagement.GetVaultRequest{VaultId: &staging.VaultID})
	if err != nil {
		return fmt.Errorf("read staging vault: %w", err)
	}
	if vault.CryptoEndpoint == nil {
		return errors.New("staging vault has no crypto endpoint")
	}
	crypto, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(factory.Provider(), *vault.CryptoEndpoint)
	if err != nil {
		return err
	}
	factory.Configure(&crypto.BaseClient, ociclient.ServiceKMS)
	digest := sha256.Sum256(record)
	signed, err := crypto.Sign(ctx, keymanagement.SignRequest{SignDataDetails: keymanagement.SignDataDetails{
		Message: common.String(base64.StdEncoding.EncodeToString(digest[:])), KeyId: &staging.SignerKeyID,
		SigningAlgorithm: keymanagement.SignDataDetailsSigningAlgorithmEcdsaSha256, MessageType: keymanagement.SignDataDetailsMessageTypeDigest}})
	if err != nil {
		return fmt.Errorf("sign staging completion: %w", err)
	}
	if signed.Signature == nil {
		return errors.New("sign staging completion: no signature")
	}
	signature, err := base64.StdEncoding.DecodeString(*signed.Signature)
	if err != nil {
		return fmt.Errorf("sign staging completion: %w", err)
	}
	if !ecdsa.VerifyASN1(u.StagingKey, digest[:], signature) {
		return errors.New("staging.signer_key_id signs with another key than staging.signer_public_key")
	}
	body, err := json.Marshal(SignedRecord{Record: record, Signature: signature})
	if err != nil {
		return err
	}
	storage, err := factory.ObjectStorage()
	if err != nil {
		return err
	}
	_, err = storage.PutObject(ctx, objectstorage.PutObjectRequest{NamespaceName: &staging.Namespace, BucketName: common.String(staging.GateBucket()),
		ObjectName: common.String(u.status.Target.Tag()), ContentLength: common.Int64(int64(len(body))), ContentType: common.String("application/json"),
		PutObjectBody: io.NopCloser(bytes.NewReader(body))})
	if err != nil {
		return fmt.Errorf("publish staging completion: %w", err)
	}
	return nil
}

func (u *Updater) latency(ctx context.Context) (LatencyVerdict, error) {
	target := *u.status.Target
	asset := releaseattest.AssetURL(target.SHA, target.RunID, LatencyAsset)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, asset, nil)
	if err != nil {
		return LatencyVerdict{}, err
	}
	response, err := u.Client.Do(request)
	if err != nil {
		return LatencyVerdict{}, fmt.Errorf("latency verdict: %w", err)
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == http.StatusNotFound:
		return LatencyVerdict{}, fmt.Errorf("latency verdict missing: %s has no %s", target.Tag(), LatencyAsset)
	case response.StatusCode != http.StatusOK:
		return LatencyVerdict{}, fmt.Errorf("latency verdict: %s answered %s", asset, response.Status)
	}
	var verdict LatencyVerdict
	if err := json.NewDecoder(io.LimitReader(response.Body, stagingMaxSize)).Decode(&verdict); err != nil {
		return LatencyVerdict{}, fmt.Errorf("latency verdict damaged: %w", err)
	}
	return verdict, verdict.validate()
}

func (u *Updater) staged(ctx context.Context, tag string) string {
	code, reason := u.verifyStaging(ctx, tag)
	if code == "" {
		stagingBlock.Store(nil)
		return ""
	}
	block := &gateBlock{region: u.Region, tag: tag, code: code, since: time.Now()}
	if held := stagingBlock.Load(); held != nil {
		block.since = held.since
	}
	stagingBlock.Store(block)
	return "staging gate " + code + ": " + reason
}

func (u *Updater) verifyStaging(ctx context.Context, tag string) (string, string) {
	staging := fleet.Embedded().Staging
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, staging.GateURL(tag), nil)
	if err != nil {
		return GateUnreadable, err.Error()
	}
	response, err := u.Client.Do(request)
	if err != nil {
		return GateUnreadable, err.Error()
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == http.StatusNotFound:
		return GateMissing, staging.Label + " has published no baked completion of " + tag
	case response.StatusCode != http.StatusOK:
		return GateUnreadable, staging.GateURL(tag) + " answered " + response.Status
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, stagingMaxSize+1))
	if err != nil {
		return GateUnreadable, err.Error()
	}
	if len(body) > stagingMaxSize {
		return GateUnsigned, fmt.Sprintf("record is over %d bytes", stagingMaxSize)
	}
	var envelope SignedRecord
	if err := json.Unmarshal(body, &envelope); err != nil {
		return GateUnsigned, "record is not a signed record: " + err.Error()
	}
	digest := sha256.Sum256(envelope.Record)
	if !ecdsa.VerifyASN1(u.StagingKey, digest[:], envelope.Signature) {
		return GateUnsigned, "signature does not verify with staging.signer_public_key"
	}
	var record StagingRecord
	if err := json.Unmarshal(envelope.Record, &record); err != nil {
		return GateUnsigned, "signed record is damaged: " + err.Error()
	}
	if record.Region != staging.Label || record.Tag != tag {
		return GateUnsigned, fmt.Sprintf("signed record is for %s %s, not %s %s", record.Region, record.Tag, staging.Label, tag)
	}
	if err := record.Latency.validate(); err != nil {
		return GateLatency, err.Error()
	}
	if record.Latency.Verdict != LatencyPass {
		return GateLatency, fmt.Sprintf("%s latency verdict for %s is %s (%s)", staging.Label, tag, record.Latency.Verdict, record.Latency.Run)
	}
	if record.Done.IsZero() || record.Baked.Sub(record.Done) < u.BakeFor {
		return GateBaking, fmt.Sprintf("%s baked %s for %s, under %s", staging.Label, tag, record.Baked.Sub(record.Done), u.BakeFor)
	}
	if age := time.Since(record.Signed); age > stagingFresh || age < -time.Minute {
		return GateStale, fmt.Sprintf("%s signed its completion of %s at %s, not within %s", staging.Label, tag, record.Signed.Format(time.RFC3339), stagingFresh)
	}
	return "", ""
}

func WriteMetrics(w io.Writer) {
	block := stagingBlock.Load()
	if block == nil {
		return
	}
	observability.WriteGauge(w, observability.Series("ts_orch_release_staging_gate_blocked_seconds", "region", block.region, "reason", block.code), time.Since(block.since).Seconds())
}
