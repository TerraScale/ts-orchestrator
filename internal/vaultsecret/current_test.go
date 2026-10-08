package vaultsecret

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
)

type currentBundle struct {
	response ocisecrets.GetSecretBundleByNameResponse
	err      error
}

func (b currentBundle) GetSecretBundleByName(_ context.Context, request ocisecrets.GetSecretBundleByNameRequest) (ocisecrets.GetSecretBundleByNameResponse, error) {
	if request.Stage != ocisecrets.GetSecretBundleByNameStageCurrent {
		return ocisecrets.GetSecretBundleByNameResponse{}, errors.New("read did not request CURRENT")
	}
	return b.response, b.err
}

func TestReadCurrentMetadataAndRedaction(t *testing.T) {
	ref := Ref{Vault: testTarget.VaultID, Name: "gru-ts-auth-signing-key-ring"}
	good := ocisecrets.SecretBundle{SecretId: new("ocid1.vaultsecret.oc1.sa-saopaulo-1.test"), VersionNumber: new(int64(7)),
		SecretBundleContent: ocisecrets.Base64SecretBundleContentDetails{Content: new(base64.StdEncoding.EncodeToString([]byte(sentinel)))}}
	read := func(bundle ocisecrets.SecretBundle) (Current, error) {
		return ReadCurrent(t.Context(), currentBundle{response: ocisecrets.GetSecretBundleByNameResponse{SecretBundle: bundle}}, ref)
	}
	value, err := read(good)
	if err != nil || value.Value() != sentinel || value.Version != 7 {
		t.Fatal("current read did not return the named version", err)
	}
	encoded, err := json.Marshal(value)
	for _, formatted := range []string{string(encoded), fmt.Sprint(value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
		if err != nil || strings.Contains(formatted, sentinel) {
			t.Fatal("metadata formatting exposed a value")
		}
	}
	for name, change := range map[string]func(*ocisecrets.SecretBundle){
		"missing version": func(b *ocisecrets.SecretBundle) { b.VersionNumber = nil },
		"zero version":    func(b *ocisecrets.SecretBundle) { b.VersionNumber = new(int64(0)) },
		"wrong region":    func(b *ocisecrets.SecretBundle) { b.SecretId = new("ocid1.vaultsecret.oc1.us-sanjose-1.test") },
		"expired":         func(b *ocisecrets.SecretBundle) { b.TimeOfExpiry = &common.SDKTime{Time: time.Now().Add(-time.Second)} },
		"oversized": func(b *ocisecrets.SecretBundle) {
			b.SecretBundleContent = ocisecrets.Base64SecretBundleContentDetails{Content: new(strings.Repeat("A", base64.StdEncoding.EncodedLen(maxValue)+4))}
		},
		"decoded oversized": func(b *ocisecrets.SecretBundle) {
			b.SecretBundleContent = ocisecrets.Base64SecretBundleContentDetails{Content: new(base64.StdEncoding.EncodeToString(make([]byte, maxValue+1)))}
		},
	} {
		b := good
		change(&b)
		if _, err := read(b); err == nil || strings.Contains(err.Error(), sentinel) {
			t.Errorf("%s was accepted or leaked contents", name)
		}
	}
	if _, err := ReadCurrent(t.Context(), currentBundle{err: errors.New(sentinel)}, ref); err == nil || strings.Contains(err.Error(), sentinel) {
		t.Fatal("an SDK error exposed its response contents")
	}
	err = &readError{name: ref.Name, cause: errors.New(sentinel)}
	if strings.Contains(fmt.Sprintf("%#v", err), sentinel) {
		t.Fatal("debug formatting exposed the underlying SDK response")
	}
}

func TestWatchPublishesChangedVersionsAndRetries(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	reads, rejected, failures := 0, false, 0
	var applied []int64
	read := func(ctx context.Context, _ map[string]Ref) (map[string]Current, error) {
		if _, bounded := ctx.Deadline(); !bounded {
			t.Fatal("read has no deadline")
		}
		reads++
		if reads == 3 {
			return nil, &readError{name: "test", cause: errors.New(sentinel)}
		}
		version := int64(1)
		if reads >= 4 && reads <= 5 {
			version = 2
		}
		if reads >= 7 {
			version = 3
		}
		return map[string]Current{"KEY_FILE": {ID: "id", Version: version, value: sentinel}}, nil
	}
	err := watch(ctx, map[string]Ref{"KEY_FILE": {}}, time.Millisecond, read,
		func(snapshot map[string]Current) error {
			version := snapshot["KEY_FILE"].Version
			if version == 2 && !rejected {
				rejected = true
				return errors.New(sentinel)
			}
			applied = append(applied, version)
			delete(snapshot, "KEY_FILE") // A consumer cannot mutate the retained snapshot.
			if len(applied) == 3 {
				cancel()
			}
			return nil
		}, func(err error) {
			failures++
			if strings.Contains(err.Error(), sentinel) {
				t.Fatal("watch exposed secret content in an error")
			}
		})
	if !errors.Is(err, context.Canceled) || !slices.Equal(applied, []int64{1, 2, 3}) || failures != 3 || reads != 7 {
		t.Fatalf("version publication/retry mismatch: reads=%d applied=%v failures=%d err=%v", reads, applied, failures, err)
	}
}

func TestDeliveryNamespaceAndFileAliases(t *testing.T) {
	for _, name := range []string{"gru-ts-auth-signing-key-ring", "gru-1-ts-auth-master-key"} {
		if err := ValidateDeliveryRefs("gru", "ts-auth", map[string]Ref{"KEY_FILE": {Vault: testTarget.VaultID, Name: name}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"sfo-ts-auth-key", "gru-netbird-pat", "gru-01-ts-auth-key", "gru-ts-auth-"} {
		if err := ValidateDeliveryRefs("gru", "ts-auth", map[string]Ref{"KEY_FILE": {Vault: testTarget.VaultID, Name: name}}, nil); err == nil {
			t.Fatalf("accepted %s", name)
		}
	}
	ref := Ref{Vault: testTarget.VaultID, Name: "gru-ts-auth-key"}
	if err := ValidateDeliveryRefs("gru", "ts-auth", map[string]Ref{"KEY_FILE": ref, "key_FILE": ref}, nil); err == nil {
		t.Fatal("accepted colliding file names")
	}
}

func TestExactDeliveryFilenamesStayWithinService(t *testing.T) {
	ref := Ref{Vault: testTarget.VaultID, Name: "gru-ts-orchestrator-controller-a-nats-credentials"}
	refs, names, err := deliveryNames("gru", "ts-orchestrator", map[string]Ref{"controller-a.creds": ref}, true)
	if err != nil || len(refs) != 1 || names["FILE_0_FILE"] != "controller-a.creds" {
		t.Fatal("could not preserve the signed credential filename", err)
	}
	for _, name := range []string{"../key", ".", "..", "/key", "nested/key", "KEY", ""} {
		if _, _, err := deliveryNames("gru", "ts-orchestrator", map[string]Ref{name: ref}, true); err == nil {
			t.Errorf("accepted unsafe filename %q", name)
		}
	}
	ref.Name = "gru-netbird-token"
	if _, _, err := deliveryNames("gru", "ts-orchestrator", map[string]Ref{"controller-a.creds": ref}, true); err == nil {
		t.Fatal("exact filename bypassed service isolation")
	}
}
