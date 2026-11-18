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
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasegate"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

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
	record, err := json.Marshal(releasegate.StagingRecord{Binaries: releasegate.ReleaseTarget(*u.status.Target).Binaries, BakeFor: u.BakeFor, Region: u.Region, Tag: u.status.Target.Tag(), Done: u.status.Done, Baked: u.status.Passed, Signed: time.Now().UTC(), Latency: latency})
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
	body, err := json.Marshal(releasegate.SignedRecord{Record: record, Signature: signature})
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

func (u *Updater) latency(ctx context.Context) (releasegate.LatencyVerdict, error) {
	target := *u.status.Target
	asset := releaseattest.AssetURL(target.SHA, target.RunID, releasegate.LatencyAsset)
	fetch, cancel := context.WithTimeout(ctx, discoverWait)
	defer cancel()
	request, err := http.NewRequestWithContext(fetch, http.MethodGet, asset, nil)
	if err != nil {
		return releasegate.LatencyVerdict{}, err
	}
	response, err := u.Client.Do(request)
	if err != nil {
		return releasegate.LatencyVerdict{}, fmt.Errorf("latency verdict: %w", err)
	}
	defer response.Body.Close()
	switch {
	case response.StatusCode == http.StatusNotFound:
		return releasegate.LatencyVerdict{}, fmt.Errorf("latency verdict missing: %s has no %s", target.Tag(), releasegate.LatencyAsset)
	case response.StatusCode != http.StatusOK:
		return releasegate.LatencyVerdict{}, fmt.Errorf("latency verdict: %s answered %s", asset, response.Status)
	}
	var verdict releasegate.LatencyVerdict
	if err := json.NewDecoder(io.LimitReader(response.Body, releasegate.MaxRecordSize)).Decode(&verdict); err != nil {
		return releasegate.LatencyVerdict{}, fmt.Errorf("latency verdict damaged: %w", err)
	}
	return verdict, verdict.Validate()
}

func (u *Updater) staged(ctx context.Context, release releaseattest.Release) string {
	_, err := (releasegate.Verifier{Client: u.Client, Attest: u.Attest, StagingKey: u.StagingKey}).Check(ctx, u.Region, release)
	if err == nil {
		stagingBlock.Store(nil)
		return ""
	}
	code := releasegate.GateUnreadable
	var refusal *releasegate.Refusal
	if errors.As(err, &refusal) {
		code = refusal.Code
	}
	block := &gateBlock{region: u.Region, tag: release.Tag(), code: code, since: time.Now()}
	if held := stagingBlock.Load(); held != nil && held.tag == block.tag {
		block.since = held.since
	}
	stagingBlock.Store(block)
	return err.Error()
}

func WriteMetrics(w io.Writer) {
	block := stagingBlock.Load()
	if block == nil {
		return
	}
	observability.WriteGauge(w, observability.Series("ts_orch_release_staging_gate_blocked_seconds", "region", block.region, "reason", block.code), time.Since(block.since).Seconds())
}
