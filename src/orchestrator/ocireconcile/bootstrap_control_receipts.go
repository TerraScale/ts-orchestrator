package ocireconcile

import "terrascale.tech/orchestrator/src/orchestrator/provider"

import (
	"context"
	"errors"
	"net/url"
	"strconv"
)

// BootstrapControlTransport resolves the owner credential reference without
// contacting OCI. Its service authority is derived from the declared region.
func BootstrapControlTransport(credentials BootstrapCredentials, region string, service provider.OCIService) (*provider.OCIHTTPTransport, error) {
	key, err := provider.ReadRSAPrivateKey(credentials.PrivateKeyPath)
	if err != nil {
		return nil, err
	}
	signer, err := provider.NewInstancePrincipalSigner(credentials.SigningKeyID(), key)
	if err != nil {
		return nil, err
	}
	host, ok := provider.OCIServiceHost(service, region)
	if !ok {
		return nil, errors.New("provider: unsupported control service")
	}
	config, err := provider.NewOCIServiceTransportConfig(service, region, "https://"+host)
	if err != nil {
		return nil, err
	}
	return provider.NewOCIHTTPTransport(config, nil, signer)
}

// ReadBootstrapControlMembers resolves logical member slots only from current
// signed OCI responses. It creates nothing and refuses ambiguous ownership.
func ReadBootstrapControlMembers(ctx context.Context, core, identity *provider.OCIHTTPTransport, tenancy, compartmentName, region string, count int) (string, []ObservedMember, error) {
	if ctx == nil || core == nil || identity == nil || core.Config.Service != provider.OCIServiceCore || identity.Config.Service != provider.OCIServiceIdentity || !provider.IsOCID(tenancy, "tenancy") || !validEstateName(compartmentName) || !validEstateName(region) || count < 1 || count > 1024 {
		return "", nil, errors.New("provider: invalid control receipt scope")
	}
	query := url.Values{"compartmentId": {tenancy}, "name": {compartmentName}}
	type compartmentReceipt struct{ ID, Name, CompartmentID, LifecycleState string }
	compartments, err := provider.ReadOCICollection[compartmentReceipt](ctx, identity, "/20160918/compartments", query)
	if err != nil {
		return "", nil, err
	}
	compartment := ""
	for _, item := range compartments {
		if item.LifecycleState == "DELETED" {
			continue
		}
		if compartment != "" || item.Name != compartmentName || item.CompartmentID != tenancy || item.LifecycleState != "ACTIVE" || !provider.IsOCID(item.ID, "compartment") {
			return "", nil, errors.New("provider: ambiguous control compartment receipt")
		}
		compartment = item.ID
	}
	if compartment == "" {
		return "", nil, errors.New("provider: control compartment has not been provisioned")
	}
	documents, err := provider.ReadOCICollection[ociMemberDocument](ctx, core, "/20160918/instances", url.Values{"compartmentId": {compartment}})
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
		if member.LifecycleState == "TERMINATED" || member.LifecycleState == "TERMINATING" || member.FreeformTags[provider.OCIManagedTag] != ManagedMemberTagValue || member.FreeformTags[provider.OCIScopeTag] != region {
			continue
		}
		if !provider.IsOCID(member.ID, "instance") || member.Index < 1 || member.Index > count || slots[member.Index-1].ID != "" || member.CompartmentID != compartment || member.DisplayName != MemberDisplayName(region, member.Index) || member.FreeformTags[MemberIndexTag] != strconv.Itoa(member.Index) || member.LifecycleState != "RUNNING" {
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
