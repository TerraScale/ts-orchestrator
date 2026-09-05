package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// BootstrapControlTransport resolves the owner credential reference without
// contacting OCI. Its service authority is derived from the declared region.
func BootstrapControlTransport(credentials BootstrapCredentials, region string, service OCIService) (*OCIHTTPTransport, error) {
	key, err := readRSAPrivateKey(credentials.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	signer, err := NewInstancePrincipalSigner(credentials.SigningKeyID(), key)
	if err != nil {
		return nil, err
	}
	host, ok := ociServiceHost(service, region)
	if !ok {
		return nil, errors.New("provider: unsupported control service")
	}
	config, err := NewOCIServiceTransportConfig(service, region, "https://"+host)
	if err != nil {
		return nil, err
	}
	return NewOCIHTTPTransport(config, nil, signer)
}

// ReadBootstrapControlMembers resolves logical member slots only from current
// signed OCI responses. It creates nothing and refuses ambiguous ownership.
func ReadBootstrapControlMembers(ctx context.Context, core, identity *OCIHTTPTransport, tenancy, compartmentName, region string, count int) (string, []ObservedMember, error) {
	if ctx == nil || core == nil || identity == nil || core.Config.Service != OCIServiceCore || identity.Config.Service != OCIServiceIdentity || !isOCID(tenancy, "tenancy") || !validEstateName(compartmentName) || !validEstateName(region) || count < 1 || count > 1024 {
		return "", nil, errors.New("provider: invalid control receipt scope")
	}
	query := url.Values{"compartmentId": {tenancy}, "name": {compartmentName}}
	type compartmentReceipt struct{ ID, Name, CompartmentID, LifecycleState string }
	compartments, err := readBootstrapControlList[compartmentReceipt](ctx, identity, "/20160918/compartments", query)
	if err != nil {
		return "", nil, err
	}
	compartment := ""
	for _, item := range compartments {
		if item.LifecycleState == "DELETED" {
			continue
		}
		if compartment != "" || item.Name != compartmentName || item.CompartmentID != tenancy || item.LifecycleState != "ACTIVE" || !isOCID(item.ID, "compartment") {
			return "", nil, errors.New("provider: ambiguous control compartment receipt")
		}
		compartment = item.ID
	}
	if compartment == "" {
		return "", nil, errors.New("provider: control compartment has not been provisioned")
	}
	documents, err := readBootstrapControlList[ociMemberDocument](ctx, core, "/20160918/instances", url.Values{"compartmentId": {compartment}})
	if err != nil {
		return "", nil, err
	}
	var members []ObservedMember
	for _, document := range documents {
		index, _ := strconv.Atoi(document.FreeformTags[MemberIndexTag])
		members = append(members, ObservedMember{ID: document.ID, DisplayName: document.DisplayName, Index: index, Shape: document.Shape, LifecycleState: document.LifecycleState, CompartmentID: document.CompartmentID, FreeformTags: document.FreeformTags})
	}
	slots := make([]ObservedMember, count)
	for _, member := range members {
		if member.LifecycleState == "TERMINATED" || member.LifecycleState == "TERMINATING" || member.FreeformTags[OCIManagedTag] != ManagedMemberTagValue || member.FreeformTags[OCIScopeTag] != region {
			continue
		}
		if !isOCID(member.ID, "instance") || member.Index < 1 || member.Index > count || slots[member.Index-1].ID != "" || member.CompartmentID != compartment || member.DisplayName != MemberDisplayName(region, member.Index) || member.FreeformTags[MemberIndexTag] != strconv.Itoa(member.Index) || member.LifecycleState != "RUNNING" {
			return "", nil, errors.New("provider: control member receipt violates declared slots")
		}
		slots[member.Index-1] = member
	}
	for _, member := range slots {
		if member.ID == "" {
			return "", nil, errors.New("provider: declared control member has not been provisioned")
		}
	}
	return compartment, slots, nil
}

func readBootstrapControlList[T any](ctx context.Context, transport *OCIHTTPTransport, path string, query url.Values) ([]T, error) {
	var result []T
	seen := map[string]bool{}
	for page := 0; page < 128; page++ {
		response, err := transport.Do(ctx, http.MethodGet, path+"?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		body, err := ReadBoundedBody(response, transport.Config.MaxBodyBytes)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			return nil, errors.New("provider: OCI control receipt read failed")
		}
		var items []T
		if json.Unmarshal(body, &items) != nil || items == nil || len(result)+len(items) > 10000 {
			return nil, errors.New("provider: invalid OCI control receipt collection")
		}
		result = append(result, items...)
		next := response.Header.Get("opc-next-page")
		if next == "" {
			return result, nil
		}
		if len(next) > 4096 || strings.ContainsAny(next, "\r\n\x00") || seen[next] {
			return nil, errors.New("provider: invalid OCI receipt pagination")
		}
		seen[next] = true
		query.Set("page", next)
	}
	return nil, errors.New("provider: OCI receipt pagination limit")
}
