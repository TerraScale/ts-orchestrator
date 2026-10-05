package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostboot"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/hostenroll"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/oci"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/terrabase"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/tsauth"
)

// staticTerraBaseMembers is the part of the signed workloads.terrabase
// profile that admits static C# TerraBase hosts: the listed members and the
// capacity of one member.
type staticTerraBaseMembers struct {
	profile  terrabase.Profile
	capacity host.Capacity
}

func newStaticTerraBaseMembers(workloads map[string]WorkloadProfile) (*staticTerraBaseMembers, error) {
	profile, ok := workloads[terrabase.Role]
	if !ok || len(profile.Env) == 0 {
		return nil, nil
	}
	parsed, err := terrabase.ParseProfile(profile.Env)
	if err != nil {
		return nil, fmt.Errorf("static TerraBase host enrollment: %w", err)
	}
	return &staticTerraBaseMembers{profile: parsed, capacity: host.Capacity(profile.Resources)}, nil
}

// enrollStatic enrolls an operator-launched C# TerraBase host. Its static
// descriptor names a node that the signed TerraBase profile lists at the
// direct peer's private address, and the instance it reports is a RUNNING
// host of this regional fleet carrying exactly that descriptor and node tag
// and no managed launch identity. The grant pins the first request to the
// instance like a managed enrollment. The registration has role terrabase,
// the capacity of one member and no managed binding; a replacement instance
// of the same node registers the next generation.
func (enrollment *managedHostEnrollment) enrollStatic(ctx context.Context, epoch uint64, peerIP string, wire []byte,
	request hostenroll.Request, descriptor hostboot.Descriptor,
) ([]byte, error) {
	if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	if descriptor.Cell != enrollment.cell || descriptor.Region != string(enrollment.region) {
		return nil, errors.New("static host descriptor is outside this regional cell")
	}
	csr, err := hostenroll.ParseCSR(request.CSRPEM)
	if err != nil {
		return nil, err
	}
	instance, err := enrollment.observeStatic(ctx, peerIP, request, descriptor)
	if err != nil {
		return nil, err
	}
	digest, err := descriptor.Digest()
	if err != nil {
		return nil, err
	}
	createKey := "static-" + descriptor.Node
	var grant hostenroll.Grant
	var revision uint64
	if request.Operation == "renew" {
		prior, _, err := enrollment.grants.Read(ctx, request.InstanceID)
		if err != nil || prior.Disabled || prior.CreateKey != createKey || prior.DescriptorSHA256 != digest {
			return nil, errors.New("host renewal has no active exact enrollment grant")
		}
		var original hostenroll.Request
		if json.Unmarshal(prior.Request, &original, json.RejectUnknownMembers(true)) != nil ||
			original.IdentityPublicKey != request.IdentityPublicKey ||
			original.NATSUserPublicKey != request.NATSUserPublicKey || original.CSRPEM != request.CSRPEM {
			return nil, errors.New("host renewal changes an enrolled identity or CSR")
		}
		if time.Since(request.IssuedAt) > 5*time.Minute && !bytes.Equal(prior.RenewalRequest, wire) {
			return nil, errStaleUnclaimedRenewal
		}
		if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
			return nil, err
		}
		grant, revision, err = enrollment.grants.ClaimRenew(ctx, request.InstanceID, wire, time.Now().UTC())
		if err != nil {
			return nil, err
		}
	} else {
		if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
			return nil, err
		}
		grant, revision, err = enrollment.grants.Claim(ctx, hostenroll.Grant{SchemaVersion: 1,
			InstanceID: request.InstanceID, CreateKey: createKey, DescriptorSHA256: digest, Request: wire})
		if err != nil {
			return nil, err
		}
	}
	cached := grant.Response
	if request.Operation == "renew" {
		cached = grant.RenewalResponse
	}
	if len(cached) != 0 {
		return cached, enrollment.fencer.Guard(ctx, epoch)
	}
	registration, err := enrollment.staticRegistration(ctx, request, descriptor, instance)
	if err != nil {
		return nil, err
	}
	receipt, err := enrollment.controller.Register(ctx, registration)
	if err != nil {
		return nil, err
	}
	jwt, chain, expires, err := enrollment.issuer.Issue(request, csr, descriptor.Node, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	response := hostenroll.Response{SchemaVersion: 1, Operation: request.Operation,
		InstanceID: request.InstanceID, Node: descriptor.Node, DescriptorSHA256: digest,
		RequestSHA256: hostenroll.RequestSHA256(wire), Nonce: request.Nonce,
		RegistrationReceipt: receipt, NATSUserJWT: jwt, TLSCertificatePEM: string(chain), ExpiresAt: expires}
	if err := response.Sign(enrollment.responseKey); err != nil {
		return nil, err
	}
	responseWire, err := protocol.EncodeJSON(response)
	if err != nil {
		return nil, err
	}
	// The instance must still hold the peer address when the credential is
	// committed and released.
	if _, err := enrollment.observeStatic(ctx, peerIP, request, descriptor); err != nil {
		return nil, err
	}
	if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	if request.Operation == "renew" {
		err = enrollment.grants.FinishRenew(ctx, grant, revision, responseWire, time.Now().UTC())
	} else {
		_, err = enrollment.grants.Finish(ctx, grant, revision, responseWire)
	}
	if err != nil {
		return nil, err
	}
	// The commit is a KV CAS that fences no epoch: release the credential
	// only while this controller still holds authority. A held host retries
	// and the current leader replays the committed response.
	if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
		return nil, err
	}
	return responseWire, nil
}

// observeStatic authenticates a static host: a TerraBase member the signed
// profile lists at the direct peer's address, or the host agent of the
// controller VM at that address.
func (enrollment *managedHostEnrollment) observeStatic(ctx context.Context, peerIP string,
	request hostenroll.Request, descriptor hostboot.Descriptor,
) (oci.CloudInstance, error) {
	if descriptor.IsController() {
		return enrollment.observeController(ctx, peerIP, request, descriptor)
	}
	if enrollment.terraBase == nil {
		return oci.CloudInstance{}, errors.New("static host enrollment requires a signed TerraBase workload profile")
	}
	peer, listed := enrollment.terraBase.profile.Peer(descriptor.Node)
	if !listed || peer.Address.Addr().String() != peerIP {
		return oci.CloudInstance{}, errors.New("static host is not a listed TerraBase member at its private address")
	}
	observer, ok := enrollment.fleet.(oci.StaticHostObserver)
	if !ok {
		return oci.CloudInstance{}, errors.New("regional fleet cannot observe static hosts")
	}
	instance, err := observer.ObserveStaticHost(ctx, request.InstanceID, descriptor.Node)
	if err != nil {
		return oci.CloudInstance{}, err
	}
	if instance.PrivateIP != peerIP || instance.Metadata[hostboot.MetadataKey] != request.Descriptor {
		return oci.CloudInstance{}, errors.New("direct peer does not match the static OCI host")
	}
	return instance, nil
}

// observeController authenticates the host agent of a controller VM: the
// direct peer is one of the signed controller addresses, and OCI shows the
// running controller of the descriptor's name holding it. The cell must
// have a ts-auth profile, the one role a controller host runs.
func (enrollment *managedHostEnrollment) observeController(ctx context.Context, peerIP string,
	request hostenroll.Request, descriptor hostboot.Descriptor,
) (oci.CloudInstance, error) {
	if _, ok := enrollment.tsAuthProfile(); !ok {
		return oci.CloudInstance{}, errors.New("controller host enrollment requires a ts-auth workload profile")
	}
	if !slices.Contains(enrollment.controllerIPs, peerIP) {
		return oci.CloudInstance{}, errors.New("controller host is not at one of this cell's controller addresses")
	}
	observer, ok := enrollment.fleet.(oci.ControllerHostObserver)
	if !ok {
		return oci.CloudInstance{}, errors.New("regional fleet cannot observe controller hosts")
	}
	instance, err := observer.ObserveControllerHost(ctx, request.InstanceID, descriptor.Node)
	if err != nil {
		return oci.CloudInstance{}, err
	}
	if instance.PrivateIP != peerIP {
		return oci.CloudInstance{}, errors.New("direct peer does not match the controller instance")
	}
	return instance, nil
}

// tsAuthProfile is the cell's current ts-auth delivery profile, from the
// signed config or its service set.
func (enrollment *managedHostEnrollment) tsAuthProfile() (WorkloadProfile, bool) {
	if enrollment.profiles == nil {
		return WorkloadProfile{}, false
	}
	profile, ok := enrollment.profiles()[tsauth.Role]
	return profile, ok
}

// staticRegistration is the registration a static host enrolls with: a
// TerraBase member with one member's capacity, or a controller host running
// one ts-auth replica.
func (enrollment *managedHostEnrollment) staticRegistration(ctx context.Context, request hostenroll.Request,
	descriptor hostboot.Descriptor, instance oci.CloudInstance,
) (host.Registration, error) {
	registration := host.Registration{Cell: enrollment.cell, Node: descriptor.Node,
		FailureDomain: strings.ToLower(instance.FaultDomain), Environment: enrollment.environment,
		PublicKey: request.IdentityPublicKey, NATSUserPublicKey: request.NATSUserPublicKey, Generation: 1}
	if descriptor.IsController() {
		profile, ok := enrollment.tsAuthProfile()
		if !ok {
			return host.Registration{}, errors.New("controller host enrollment requires a ts-auth workload profile")
		}
		registration.Roles, registration.Capacity = []string{tsauth.Role}, host.Capacity(profile.Resources)
	} else {
		registration.Roles, registration.Capacity = []string{terrabase.Role}, enrollment.terraBase.capacity
	}
	statuses, err := enrollment.controller.ListHosts(ctx)
	if err != nil {
		return host.Registration{}, err
	}
	return nextStaticRegistration(registration, statuses)
}

// nextStaticRegistration keeps the node's current generation when nothing
// changed and otherwise registers the next one. New keys are refused early
// while the node's host holds a session. The guarantee is in session
// acquisition (host.sessionHeld): the next generation of a host without a
// managed binding cannot acquire a session until the previous one expires,
// so a replacement never runs beside the host it replaces.
func nextStaticRegistration(registration host.Registration, statuses []host.HostStatus) (host.Registration, error) {
	for _, status := range statuses {
		current := status.Registration
		if current.Node != registration.Node {
			continue
		}
		registration.Generation = current.Generation
		if sameJSONValue(current, registration) {
			return registration, nil
		}
		if (current.PublicKey != registration.PublicKey || current.NATSUserPublicKey != registration.NATSUserPublicKey) &&
			!status.SessionExpiresAt.IsZero() {
			return host.Registration{}, fmt.Errorf("%s still has a current host session; its replacement enrolls once that session ends", registration.Node)
		}
		registration.Generation++
	}
	return registration, nil
}

func sameJSONValue(left, right host.Registration) bool {
	a, errA := protocol.EncodeJSON(left)
	b, errB := protocol.EncodeJSON(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

// revokeStatic disables a static host's enrollment grant, so the instance
// can neither renew nor enroll again. Credentials already issued expire
// within their 48-hour lifetime, as for a managed host.
func (enrollment *managedHostEnrollment) revokeStatic(ctx context.Context, epoch uint64, instanceID string,
	grant hostenroll.Grant, request hostenroll.Request, descriptor hostboot.Descriptor,
) (hostEnrollmentRevokeReceipt, error) {
	digest, err := descriptor.Digest()
	if err != nil || request.Operation != "enroll" || request.InstanceID != instanceID ||
		descriptor.Cell != enrollment.cell || descriptor.Region != string(enrollment.region) ||
		grant.CreateKey != "static-"+descriptor.Node || grant.DescriptorSHA256 != digest {
		return hostEnrollmentRevokeReceipt{}, errors.New("static host enrollment grant is not bound to this regional cell")
	}
	if err := enrollment.fencer.Guard(ctx, epoch); err != nil {
		return hostEnrollmentRevokeReceipt{}, err
	}
	revision, err := enrollment.grants.Disable(ctx, instanceID)
	if err != nil {
		return hostEnrollmentRevokeReceipt{}, err
	}
	return hostEnrollmentRevokeReceipt{InstanceID: instanceID, GrantRevision: revision, Disabled: true}, nil
}
