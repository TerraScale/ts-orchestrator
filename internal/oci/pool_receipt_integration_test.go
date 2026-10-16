package oci

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func TestPoolReceiptsRetainOriginalSDKResultsAfterDiskRestartWithoutMintingAdmission(t *testing.T) {
	const configurationID = "ocid1.instanceconfiguration.oc1..original"
	const poolID = "ocid1.instancepool.oc1..original"
	config := natscell.Config{Cell: "lab", Instance: "pool-receipts", Replicas: 1, Lab: true,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: -1, StoreDir: filepath.Join(t.TempDir(), "jetstream")}}
	runtime, err := natscell.Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	journal, err := OpenJournal(t.Context(), runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" || r.Header.Get("opc-retry-token") == "" {
			t.Error("actual SDK mutation lacks signed request or stable retry identity")
			http.Error(w, "rejected", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("opc-request-id", "original-sdk-response")
		switch r.URL.Path {
		case "/20160918/instanceConfigurations":
			fmt.Fprintf(w, `{"id":%q,"compartmentId":"ocid1.compartment.oc1..owned","instanceDetails":{"instanceType":"compute","launchDetails":{"shape":"VM.Standard.A1.Flex"}}}`, configurationID)
		case "/20160918/instancePools":
			fmt.Fprintf(w, `{"id":%q,"compartmentId":"ocid1.compartment.oc1..owned","instanceConfigurationId":%q,"size":0}`, poolID, configurationID)
		case "/20160918/instancePools/" + poolID:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			if strings.Contains(string(body), configurationID) {
				fmt.Fprintf(w, `{"id":%q,"compartmentId":"ocid1.compartment.oc1..owned","instanceConfigurationId":"ocid1.instanceconfiguration.oc1..previous","size":0}`, poolID)
				return
			}
			fmt.Fprintf(w, `{"id":%q,"compartmentId":"ocid1.compartment.oc1..owned","instanceConfigurationId":%q,"size":1}`, poolID, configurationID)
		default:
			t.Errorf("unexpected SDK endpoint: %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test", "sa-saopaulo-1", "test",
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})), nil)
	factory, err := ociclient.New(provider, ociclient.Options{Region: "sa-saopaulo-1", Retry: ociclient.RetryOptions{MaxAttempts: 1}})
	if err != nil {
		t.Fatal(err)
	}
	management, err := factory.ComputeManagement()
	if err != nil {
		t.Fatal(err)
	}
	ociclient.PinHost(&management.BaseClient, server.URL)
	details := core.ComputeInstanceDetails{LaunchDetails: &core.InstanceConfigurationLaunchInstanceDetails{Shape: new("VM.Standard.A1.Flex")}}
	configurationSHA, err := PoolConfigurationSHA256(details)
	if err != nil {
		t.Fatal(err)
	}
	original := PoolCreateRequest{OperationID: entityid.New(), Kind: PoolCreateConfiguration, RecipeSHA256: strings.Repeat("a", 64),
		LogicalScopeSHA256: strings.Repeat("b", 64), ResolvedScopeSHA256: strings.Repeat("b", 64), GrantSHA256: strings.Repeat("c", 64), GrantGeneration: 7,
		TenancyID: "ocid1.tenancy.oc1..test", Region: RegionGRU, CompartmentID: "ocid1.compartment.oc1..owned", Role: "container", Architecture: "arm64", Shape: "VM.Standard.A1.Flex",
		ConfigurationSHA256: configurationSHA, RequestSHA256: strings.Repeat("d", 64), RetryToken: entityid.New(), Currency: "USD",
		ReservedMonthlyCents: 2147, QuoteSHA256: strings.Repeat("e", 64), StartedAt: time.Now().UTC()}
	if err := journal.RecordPoolCreateRequest(t.Context(), original); err != nil {
		t.Fatal(err)
	}
	created, err := management.CreateInstanceConfiguration(t.Context(), core.CreateInstanceConfigurationRequest{OpcRetryToken: new(original.RetryToken),
		CreateInstanceConfiguration: core.CreateInstanceConfigurationDetails{CompartmentId: new(original.CompartmentID), InstanceDetails: details}})
	if err != nil {
		t.Fatal(err)
	}
	readbackSHA, err := PoolConfigurationSHA256(created.InstanceDetails)
	if err != nil || readbackSHA != configurationSHA {
		t.Fatalf("SDK create/readback normalization differs: %q != %q err=%v", configurationSHA, readbackSHA, err)
	}
	if err := journal.RecordPoolCreateResult(t.Context(), original.OperationID, original.Kind, *created.Id, *created.OpcRequestId); err != nil {
		t.Fatal(err)
	}
	placements := []core.CreateInstancePoolPlacementConfigurationDetails{{AvailabilityDomain: new("AD-1"), PrimaryVnicSubnets: &core.InstancePoolPlacementPrimarySubnet{SubnetId: new("ocid1.subnet.oc1..owned")}}}
	poolRequest := original
	poolRequest.Kind, poolRequest.ConfigurationID, poolRequest.RetryToken = PoolCreatePool, configurationID, entityid.New()
	poolRequest.PlacementSHA256, err = PoolPlacementSHA256(placements)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordPoolCreateRequest(t.Context(), poolRequest); err != nil {
		t.Fatal(err)
	}
	pool, err := management.CreateInstancePool(t.Context(), core.CreateInstancePoolRequest{OpcRetryToken: new(poolRequest.RetryToken),
		CreateInstancePoolDetails: core.CreateInstancePoolDetails{CompartmentId: new(original.CompartmentID), InstanceConfigurationId: new(configurationID), Size: new(0), PlacementConfigurations: placements}})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordPoolCreateResult(t.Context(), original.OperationID, PoolCreatePool, *pool.Id, *pool.OpcRequestId); err != nil {
		t.Fatal(err)
	}
	growth := CapacityRequest{OperationID: original.OperationID, RecipeSHA256: original.RecipeSHA256, LogicalScopeSHA256: original.LogicalScopeSHA256,
		ResolvedScopeSHA256: original.ResolvedScopeSHA256, GrantSHA256: original.GrantSHA256, GrantGeneration: original.GrantGeneration,
		TenancyID: original.TenancyID, Region: original.Region, CompartmentID: original.CompartmentID, PoolID: poolID,
		RequestSHA256: strings.Repeat("f", 64), RetryToken: entityid.New(), IfMatch: "original-etag", Currency: original.Currency,
		ReservedMonthlyCents: original.ReservedMonthlyCents, QuoteSHA256: original.QuoteSHA256, TargetSize: 1, StartedAt: original.StartedAt}
	pointBase := growth
	pointBase.TargetSize, pointBase.RetryToken, pointBase.IfMatch = 0, entityid.New(), "original-point-etag"
	point := PoolPointRequest{Request: pointBase, ConfigurationID: configurationID, ConfigurationSHA256: configurationSHA, PlacementSHA256: poolRequest.PlacementSHA256}
	if err := journal.RecordPoolPointRequest(t.Context(), point); err != nil {
		t.Fatal(err)
	}
	accepted, err := management.UpdateInstancePool(t.Context(), core.UpdateInstancePoolRequest{InstancePoolId: new(poolID), IfMatch: new(pointBase.IfMatch),
		OpcRetryToken: new(pointBase.RetryToken), UpdateInstancePoolDetails: core.UpdateInstancePoolDetails{InstanceConfigurationId: new(configurationID)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordPoolPointResult(t.Context(), original.OperationID, accepted); err != nil {
		t.Fatalf("asynchronous old config readback was confused with rejected SDK acceptance: %v", err)
	}
	if err := journal.RecordCapacityRequest(t.Context(), growth); err != nil {
		t.Fatal(err)
	}
	updated, err := management.UpdateInstancePool(t.Context(), core.UpdateInstancePoolRequest{InstancePoolId: new(poolID), IfMatch: new(growth.IfMatch),
		OpcRetryToken: new(growth.RetryToken), UpdateInstancePoolDetails: core.UpdateInstancePoolDetails{Size: new(1)}})
	if err != nil {
		t.Fatal(err)
	}
	foreign := updated
	foreign.CompartmentId = new("ocid1.compartment.oc1..foreign")
	oversized := updated
	oversized.Size = new(10)
	if journal.RecordCapacityResult(t.Context(), original.OperationID, foreign) == nil || journal.RecordCapacityResult(t.Context(), original.OperationID, oversized) == nil {
		t.Fatal("foreign compartment or oversized SDK effect became exact capacity result")
	}
	if err := journal.RecordCapacityResult(t.Context(), original.OperationID, updated); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after the immutable result but before its resource index.
	if err := journal.kv.Delete(t.Context(), poolResourceKey(poolID)); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = natscell.Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	journal, err = OpenJournal(t.Context(), runtime.JetStream(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.RecordPoolCreateResult(t.Context(), original.OperationID, PoolCreatePool, poolID, "later-idempotent-response"); err != nil {
		t.Fatal(err)
	}
	got, result, found, err := journal.GetPoolCreateResource(t.Context(), poolID)
	if err != nil || !found || got != poolRequest || result.OpcRequestID != "original-sdk-response" {
		t.Fatalf("original request/result or repaired resource index lost: %+v %+v found=%v err=%v", got, result, found, err)
	}
	if _, found, err := journal.GetCapacityResult(t.Context(), original.OperationID); err != nil || !found {
		t.Fatalf("positive growth result lost on restart: found=%v err=%v", found, err)
	}
	if saved, found, err := journal.GetPoolPointRequest(t.Context(), original.OperationID); err != nil || !found || saved != point {
		t.Fatalf("point and growth collided or original point request lost: %+v found=%v err=%v", saved, found, err)
	}
	if saved, found, err := journal.GetPoolPointResult(t.Context(), original.OperationID); err != nil || !found || saved.ObservedConfigurationID != "ocid1.instanceconfiguration.oc1..previous" || saved.ObservedSize != 0 {
		t.Fatalf("SDK acceptance manufactured new asynchronous configuration: %+v found=%v err=%v", saved, found, err)
	}
	changedPoint := point
	changedPoint.Request.IfMatch = "refreshed-point-etag"
	if journal.RecordPoolPointRequest(t.Context(), changedPoint) == nil {
		t.Fatal("changed point precondition replaced original unknown attempt")
	}
	altered := original
	altered.QuoteSHA256 = strings.Repeat("1", 64)
	if journal.RecordPoolCreateRequest(t.Context(), altered) == nil || journal.RecordPoolCreateResult(t.Context(), original.OperationID, PoolCreatePool, "ocid1.instancepool.oc1..foreign", "foreign-response") == nil {
		t.Fatal("changed request or returned resource replaced original provenance")
	}
	proof, err := journal.VerifyPoolInstance(t.Context(), factory, "ocid1.instance.oc1..foreign-attached")
	if !errors.Is(err, ErrPoolCreationLineagePending) || proof.IsVerified() || proof.Revalidate(t.Context()) == nil {
		t.Fatalf("pool consistency observations minted original child creation admission: %+v err=%v", proof, err)
	}
}
