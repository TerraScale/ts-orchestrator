package app

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

// staticTerraBaseMembers is the part of the effective terrabase profile that
// admits static C# TerraBase hosts: the listed members and the capacity of
// one member.
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
	instance, admission, err := enrollment.observeStatic(ctx, peerIP, request, descriptor)
	if err != nil {
		return nil, err
	}
	digest, err := descriptor.Digest()
	if err != nil {
		return nil, err
	}
	createKey := entityid.Derive("static-enrollment", enrollment.cell, descriptor.Node)
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
	jwt, chain, expires, err := enrollment.issuer.Issue(request, csr, descriptor.Node, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	// The instance must still hold the peer address, under the admission it
	// registered with, when the credential is committed and released. A cell
	// spec adopted mid-request can change the admission: the registration
	// and response then settle on the one the last observation found.
	var responseWire []byte
	for attempt := 1; ; attempt++ {
		registration, err := enrollment.staticRegistration(ctx, request, descriptor, instance, admission)
		if err != nil {
			return nil, err
		}
		receipt, err := enrollment.controller.Register(ctx, registration)
		if err != nil {
			return nil, err
		}
		response := hostenroll.Response{SchemaVersion: 1, Operation: request.Operation,
			InstanceID: request.InstanceID, Node: descriptor.Node, DescriptorSHA256: digest,
			RequestSHA256: hostenroll.RequestSHA256(wire), Nonce: request.Nonce,
			RegistrationReceipt: receipt, Roles: admission.roles(),
			NATSUserJWT: jwt, TLSCertificatePEM: string(chain), ExpiresAt: expires}
		if enrollment.services != nil {
			response.NetBird = enrollment.services.netbird()
		}
		if err := response.Sign(enrollment.responseKey); err != nil {
			return nil, err
		}
		if responseWire, err = protocol.EncodeJSON(response); err != nil {
			return nil, err
		}
		responseWire, err = enrollment.prepareRuntimeWorker(ctx, epoch, wire, responseWire)
		if err != nil {
			return nil, err
		}
		var again staticAdmission
		if instance, again, err = enrollment.observeStatic(ctx, peerIP, request, descriptor); err != nil {
			return nil, err
		}
		if reflect.DeepEqual(again, admission) {
			break
		}
		if attempt == 3 {
			return nil, errors.New("the cell spec keeps changing how this static host enrolls; retry")
		}
		admission = again
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

// staticMember returns node's TerraBase peer and one member's capacity when
// the effective terrabase profile lists it: the cell spec's entry, which only
// a root may sign, or else the signed controller config's. The registry
// adopts only profiles that parse, so a parse error lists nothing.
func (enrollment *managedHostEnrollment) staticMember(node string) (terrabase.Peer, host.Capacity, bool) {
	members, err := newStaticTerraBaseMembers(enrollment.services.profiles())
	if err != nil || members == nil {
		return terrabase.Peer{}, host.Capacity{}, false
	}
	peer, listed := members.profile.Peer(node)
	return peer, members.capacity, listed
}

// staticAdmission is how a static host enrolls, decided once per request
// and checked again before the credential is released: as a member the
// effective TerraBase profile lists, by a cell spec host grant, or as a node
// of the cell's pool with the cell's service roles.
type staticAdmission struct {
	Grant    *cellspec.HostGrant
	Capacity host.Capacity
	Pool     bool
	Roles    []string
}

// roles are the roles an enrollment response lists: a granted host's roles,
// a pool node's service roles; a TerraBase member's role is implied.
func (admission staticAdmission) roles() []string {
	if admission.Pool {
		return admission.Roles
	}
	if admission.Grant == nil {
		return nil
	}
	return admission.Grant.Roles
}

// observeStatic authenticates a static host: a host the cell spec grants the
// direct peer's address, a TerraBase member it colocates included, a node of
// the cell's pool, or else a TerraBase member the effective profile lists at
// that address.
func (enrollment *managedHostEnrollment) observeStatic(ctx context.Context, peerIP string,
	request hostenroll.Request, descriptor hostboot.Descriptor,
) (oci.CloudInstance, staticAdmission, error) {
	peer, capacity, listed := enrollment.staticMember(descriptor.Node)
	_, _, granted := enrollment.services.hostGrant(descriptor.Node)
	if !granted && !listed && enrollment.pool != nil {
		return enrollment.observePoolNode(ctx, peerIP, request, descriptor)
	}
	if granted || !listed {
		return enrollment.observeGranted(ctx, peerIP, request, descriptor)
	}
	if peer.Address.Addr().String() != peerIP {
		return oci.CloudInstance{}, staticAdmission{}, errors.New("static host is not a listed TerraBase member at its private address")
	}
	observer, ok := enrollment.fleet.(oci.StaticHostObserver)
	if !ok {
		return oci.CloudInstance{}, staticAdmission{}, errors.New("regional fleet cannot observe static hosts")
	}
	instance, err := observer.ObserveStaticHost(ctx, request.InstanceID, descriptor.Node)
	if err != nil {
		return oci.CloudInstance{}, staticAdmission{}, err
	}
	if instance.PrivateIP != peerIP || instance.Metadata[hostboot.MetadataKey] != request.Descriptor {
		return oci.CloudInstance{}, staticAdmission{}, errors.New("direct peer does not match the static OCI host")
	}
	return instance, staticAdmission{Capacity: capacity}, nil
}

// observeGranted authenticates a host the adopted cell spec grants: the
// direct peer holds the grant's address, and OCI shows the running instance
// of the descriptor's name holding it.
func (enrollment *managedHostEnrollment) observeGranted(ctx context.Context, peerIP string,
	request hostenroll.Request, descriptor hostboot.Descriptor,
) (oci.CloudInstance, staticAdmission, error) {
	grant, capacity, ok := enrollment.services.hostGrant(descriptor.Node)
	if !ok || grant.PrivateIP != peerIP {
		return oci.CloudInstance{}, staticAdmission{}, errors.New("static host is neither a listed TerraBase member nor granted its private address")
	}
	observer, ok := enrollment.fleet.(oci.NamedHostObserver)
	if !ok {
		return oci.CloudInstance{}, staticAdmission{}, errors.New("regional fleet cannot observe granted hosts")
	}
	instance, err := observer.ObserveNamedHost(ctx, request.InstanceID, descriptor.Node)
	if err != nil {
		return oci.CloudInstance{}, staticAdmission{}, err
	}
	if instance.PrivateIP != peerIP {
		return oci.CloudInstance{}, staticAdmission{}, errors.New("direct peer does not match the granted instance")
	}
	return instance, staticAdmission{Grant: &grant, Capacity: capacity}, nil
}

// observePoolNode authenticates a node pool instance: OCI shows it RUNNING in
// this cell's pool under the node's name at the direct peer's address, and
// tagged as a node of this cell. Its shape sets the capacity.
func (enrollment *managedHostEnrollment) observePoolNode(ctx context.Context, peerIP string,
	request hostenroll.Request, descriptor hostboot.Descriptor,
) (oci.CloudInstance, staticAdmission, error) {
	// Nodes 1 to 3 are the quorum nodes, never pool instances.
	if number, err := strconv.Atoi(descriptor.Node[strings.LastIndexByte(descriptor.Node, '-')+1:]); err != nil ||
		number < nodescale.FirstPoolNode {
		return oci.CloudInstance{}, staticAdmission{}, errors.New("a pool node is numbered from 4")
	}
	state, err := enrollment.pool.Observe(ctx)
	if err != nil {
		return oci.CloudInstance{}, staticAdmission{}, err
	}
	if !slices.ContainsFunc(state.Instances, func(member nodescale.PoolInstance) bool {
		return member.ID == request.InstanceID && member.Name == descriptor.Node &&
			member.State == "RUNNING" && member.PrivateIP == peerIP
	}) {
		return oci.CloudInstance{}, staticAdmission{}, errors.New("static host is not a running node of this cell's pool at its private address")
	}
	observer, ok := enrollment.fleet.(oci.NamedHostObserver)
	if !ok {
		return oci.CloudInstance{}, staticAdmission{}, errors.New("regional fleet cannot observe pool nodes")
	}
	instance, err := observer.ObserveNamedHost(ctx, request.InstanceID, descriptor.Node)
	if err != nil {
		return oci.CloudInstance{}, staticAdmission{}, err
	}
	if instance.PrivateIP != peerIP || instance.FreeformTags[poolTagCell] != enrollment.cell ||
		instance.FreeformTags[poolTagRole] != poolNodeRole {
		return oci.CloudInstance{}, staticAdmission{}, errors.New("pool node does not match its OCI instance")
	}
	if instance.Ocpus == nil || instance.MemoryInGBs == nil || *instance.Ocpus < 1 || *instance.MemoryInGBs < 1 {
		return oci.CloudInstance{}, staticAdmission{}, errors.New("pool node has no OCI shape")
	}
	capacity := host.Capacity{CPU: int(*instance.Ocpus), MemoryBytes: int64(*instance.MemoryInGBs) << 30,
		DiskBytes: nodescale.BootVolumeGB << 30}
	return instance, staticAdmission{Pool: true, Roles: enrollment.poolRoles(), Capacity: capacity}, nil
}

// poolRoles are the roles a pool node runs: every reconciled service's role
// except the TerraBase member's.
func (enrollment *managedHostEnrollment) poolRoles() []string {
	_, specs := enrollment.services.effective()
	var roles []string
	for _, spec := range specs {
		if spec.Role != terrabase.Role {
			roles = append(roles, spec.Role)
		}
	}
	slices.Sort(roles)
	return slices.Compact(roles)
}

// staticRegistration is the registration a static host enrolls with: a
// TerraBase member with one member's capacity, a granted host with its
// grant's roles and environment, or a pool node with the cell's service roles.
func (enrollment *managedHostEnrollment) staticRegistration(ctx context.Context, request hostenroll.Request,
	descriptor hostboot.Descriptor, instance oci.CloudInstance, admission staticAdmission,
) (host.Registration, error) {
	registration := host.Registration{ID: entityid.Derive("host", enrollment.cell, descriptor.Node), Cell: enrollment.cell, Node: descriptor.Node,
		FailureDomain: strings.ToLower(instance.FaultDomain), Environment: enrollment.environment,
		PublicKey: request.IdentityPublicKey, NATSUserPublicKey: request.NATSUserPublicKey, Generation: 1}
	registration.Roles, registration.Capacity = []string{terrabase.Role}, admission.Capacity
	if grant := admission.Grant; grant != nil {
		registration.Roles, registration.Environment = grant.Roles, grant.Environment
	}
	if admission.Pool {
		registration.Roles = admission.Roles
	}
	statuses, err := enrollment.controller.ListHosts(ctx)
	if err != nil {
		return host.Registration{}, err
	}
	registration, err = nextStaticRegistration(registration, statuses)
	if err != nil {
		return host.Registration{}, err
	}
	// A scale-down retires its node's name for reuse. OCI has just shown a new
	// instance under that name, so it may take it again. The same host renewing
	// keeps its keys and stays retired: it may be draining.
	if admission.Pool && slices.ContainsFunc(statuses, func(status host.HostStatus) bool {
		return status.Registration.Node == descriptor.Node && status.Retired &&
			status.Registration.PublicKey != request.IdentityPublicKey
	}) {
		if err := enrollment.controller.Unretire(ctx, descriptor.Node); err != nil {
			return host.Registration{}, err
		}
	}
	return registration, nil
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
		grant.CreateKey != entityid.Derive("static-enrollment", enrollment.cell, descriptor.Node) || grant.DescriptorSHA256 != digest {
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
