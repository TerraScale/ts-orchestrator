package vaultsecret

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
)

type versionVault struct {
	metadata ocivault.GetSecretResponse
	updates  []ocivault.UpdateSecretRequest
	err      error
}

func (v *versionVault) GetSecret(context.Context, ocivault.GetSecretRequest) (ocivault.GetSecretResponse, error) {
	return v.metadata, nil
}
func (v *versionVault) UpdateSecret(_ context.Context, request ocivault.UpdateSecretRequest) (ocivault.UpdateSecretResponse, error) {
	v.updates = append(v.updates, request)
	return ocivault.UpdateSecretResponse{Secret: ocivault.Secret{Id: request.SecretId,
		CurrentVersionNumber: new(*v.metadata.CurrentVersionNumber + 1)}}, v.err
}

func TestPublishVersionRequiresExactTargetAndConcurrentVersion(t *testing.T) {
	ref := Ref{Vault: testTarget.VaultID, Name: "gru-ts-auth-signing-key-ring"}
	id := "ocid1.vaultsecret.oc1.sa-saopaulo-1.ring"
	metadata := ocivault.GetSecretResponse{Etag: new("revision-7"), Secret: ocivault.Secret{
		Id: new(id), VaultId: new(ref.Vault), SecretName: new(ref.Name), CurrentVersionNumber: new(int64(7)),
		LifecycleState: ocivault.SecretLifecycleStateActive}}
	client := &versionVault{metadata: metadata}
	stored, err := PublishVersion(t.Context(), client, ref, id, 7, []byte(sentinel))
	if err != nil || stored.ID != id || len(client.updates) != 1 {
		t.Fatal("publication did not reach the intended existing secret", err)
	}
	request := client.updates[0]
	content := request.SecretContent.(ocivault.Base64SecretContentDetails)
	decoded, err := base64.StdEncoding.DecodeString(*content.Content)
	if err != nil || string(decoded) != sentinel || *request.IfMatch != "revision-7" || *request.SecretId != id || content.Stage != ocivault.SecretContentDetailsStageCurrent {
		t.Fatal("publication did not bind the content, CURRENT stage, OCID and ETag")
	}
	for name, change := range map[string]func(*ocivault.GetSecretResponse){
		"different Vault":        func(m *ocivault.GetSecretResponse) { m.VaultId = new("other") },
		"different name":         func(m *ocivault.GetSecretResponse) { m.SecretName = new("gru-netbird-key") },
		"deleting":               func(m *ocivault.GetSecretResponse) { m.LifecycleState = ocivault.SecretLifecycleStatePendingDeletion },
		"missing ETag":           func(m *ocivault.GetSecretResponse) { m.Etag = nil },
		"concurrent publication": func(m *ocivault.GetSecretResponse) { m.CurrentVersionNumber = new(int64(8)) },
	} {
		before := metadata
		change(&before)
		client := &versionVault{metadata: before}
		_, err := PublishVersion(t.Context(), client, ref, id, 7, []byte(sentinel))
		if err == nil || len(client.updates) != 0 || strings.Contains(err.Error(), sentinel) {
			t.Errorf("%s accepted a write or exposed its contents", name)
		}
		if name == "concurrent publication" && !errors.Is(err, ErrVersionConflict) {
			t.Fatal("missing version conflict")
		}
	}
	client = &versionVault{metadata: metadata, err: errors.New(sentinel)}
	if _, err := PublishVersion(t.Context(), client, ref, id, 7, []byte(sentinel)); err == nil || strings.Contains(err.Error(), sentinel) {
		t.Fatal("publication exposed an SDK response body")
	}
}
