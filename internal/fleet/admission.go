package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
	"github.com/TerraScale/ts-orchestrator/internal/releasegate"
	"github.com/oracle/oci-go-sdk/v65/core"
)

var admissionTag = regexp.MustCompile("^ci-([0-9a-f]{40})-run-([0-9]{1,20})$")

func admitNodeRelease(ctx context.Context, staging Staging, region string, release releaseattest.Release) (releasegate.Receipt, error) {
	key, err := staging.Signer()
	if err != nil {
		return releasegate.Receipt{}, err
	}
	attest, err := releaseattest.PublicGood()
	if err != nil {
		return releasegate.Receipt{}, err
	}
	verifier := releasegate.Verifier{Client: &http.Client{Timeout: time.Minute}, Attest: attest, StagingKey: key}
	return verifier.Check(ctx, region, release, releasegate.Launch)
}

func admitConfiguration(ctx context.Context, staging Staging, region, data string) error {
	var receipt releasegate.Receipt
	if err := json.Unmarshal([]byte(data), &receipt); err != nil {
		return err
	}
	parts := admissionTag.FindStringSubmatch(receipt.Tag)
	if parts == nil || receipt.Region != region {
		return fmt.Errorf("configuration has no admission for %s", region)
	}
	release := releaseattest.Release{SHA: parts[1], RunID: parts[2], Binaries: map[string]releaseattest.Artifact{}}
	for arch, digest := range receipt.Binaries {
		release.Binaries[arch] = releaseattest.Artifact{SHA256: digest}
	}
	_, err := admitNodeRelease(ctx, staging, region, release)
	if err != nil {
		return err
	}
	return nil
}

func AdmittedNodeRelease(ctx context.Context, document Fleet, region Region) (releaseattest.Release, releasegate.Receipt, error) {
	release, err := newestNodeRelease(ctx)
	if err != nil {
		return releaseattest.Release{}, releasegate.Receipt{}, err
	}
	if err := release.knows(region); err != nil {
		return releaseattest.Release{}, releasegate.Receipt{}, err
	}
	receipt, err := admitNodeRelease(ctx, document.Staging, region.Label, release.attested)
	return release.attested, receipt, err
}

func AdmitInstanceConfiguration(ctx context.Context, document Fleet, region Region, id *string) error {
	if id == nil || *id == "" {
		return fmt.Errorf("replacement has no admitted instance configuration")
	}
	factory, err := ociclient.InstancePrincipalContext(ctx, region.OCIRegion)
	if err != nil {
		return err
	}
	client, err := factory.ComputeManagement()
	if err != nil {
		return err
	}
	configuration, err := client.GetInstanceConfiguration(ctx, core.GetInstanceConfigurationRequest{InstanceConfigurationId: id})
	if err != nil {
		return err
	}
	details, ok := configuration.InstanceDetails.(core.ComputeInstanceDetails)
	if !ok || details.LaunchDetails == nil {
		return fmt.Errorf("replacement configuration has no launch details")
	}
	return admitConfiguration(ctx, document.Staging, region.Label, details.LaunchDetails.Metadata["release_admission"])
}
