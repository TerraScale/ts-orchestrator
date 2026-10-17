package oci

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestVolumeBackupSDKRechecksRequestGuard(t *testing.T) {
	denied := errors.New("original root session revoked")
	for name, run := range map[string]func(context.Context, *sdkProvider) error{
		"create": func(ctx context.Context, provider *sdkProvider) error {
			_, err := provider.CreateVolumeBackup(ctx, "ocid1.volume.exact", "backup", "FULL", nil, "original-token")
			return err
		},
		"list volume": func(ctx context.Context, provider *sdkProvider) error {
			_, err := provider.ListVolumeBackups(ctx, "ocid1.volume.exact")
			return err
		},
		"list compartment": func(ctx context.Context, provider *sdkProvider) error {
			_, err := provider.ListCompartmentVolumeBackups(ctx)
			return err
		},
		"get": func(ctx context.Context, provider *sdkProvider) error {
			_, err := provider.GetVolumeBackup(ctx, "ocid1.volumebackup.exact")
			return err
		},
		"delete": func(ctx context.Context, provider *sdkProvider) error {
			return provider.DeleteVolumeBackup(ctx, "ocid1.volumebackup.exact", "original-etag")
		},
	} {
		t.Run(name, func(t *testing.T) {
			config, _ := testRegionConfig()
			recorder := &terminalSDKRecorder{}
			base := common.BaseClient{Host: "https://sdk.test.invalid", BasePath: "20160918",
				Signer: observeSDKSigner{}, HTTPClient: recorder}
			ociclient.ConfigureRequestCancellation(&base)
			provider := &sdkProvider{config: config, storage: core.BlockstorageClient{BaseClient: base}}
			ctx := ociclient.WithRequestGuard(t.Context(), func(context.Context) error { return denied })
			if err := run(ctx, provider); !errors.Is(err, denied) {
				t.Fatalf("revoked operation returned %v", err)
			}
			if len(recorder.requests) != 0 {
				t.Fatal("revoked session reached the provider")
			}
		})
	}
}

type terminatedBackupSDK struct{ config RegionConfig }

func (sdk terminatedBackupSDK) Do(request *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"id":"ocid1.volume.exact","compartmentId":"` + sdk.config.CompartmentID +
			`","availabilityDomain":"` + sdk.config.AvailabilityDomain + `","lifecycleState":"TERMINATED"}`)), Request: request}, nil
}

func TestVolumeBackupTerminationCheckpointRechecksAuthority(t *testing.T) {
	config, _ := testRegionConfig()
	journal, err := NewKVJournal(testJournalBucket(t))
	if err != nil {
		t.Fatal(err)
	}
	denied := errors.New("original backup authority revoked after observation")
	base := common.BaseClient{Host: "https://sdk.test.invalid", BasePath: "20160918",
		Signer: observeSDKSigner{}, HTTPClient: terminatedBackupSDK{config}}
	ociclient.ConfigureRequestCancellation(&base)
	provider := &sdkProvider{config: config, terminations: journal,
		storage: core.BlockstorageClient{BaseClient: base}, backupGuard: func(context.Context) error { return denied }}
	if gone, err := provider.VolumeGone(t.Context(), "ocid1.volume.exact"); gone || !errors.Is(err, denied) {
		t.Fatalf("revoked termination checkpoint: gone=%v err=%v", gone, err)
	}
	if gone, err := journal.volumeTerminated(t.Context(), config, "ocid1.volume.exact"); gone || err != nil {
		t.Fatalf("revoked observation became durable: gone=%v err=%v", gone, err)
	}
}
