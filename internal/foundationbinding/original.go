package foundationbinding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

// CreateIdentity contains no payloads. The regional journal binds it to its
// authenticated operation and signed intent before OCI receives the request.
type CreateIdentity = createRequest

func (identity CreateIdentity) Validate() error {
	digest, err := hex.DecodeString(identity.RequestDigest)
	_, region := catalog.CellForOCIRegion(identity.Region)
	if identity.Key == "" || len(identity.Key) > 128 || strings.ContainsAny(identity.Key, "\x00\r\n/\\") || !region || err != nil || len(digest) != 32 {
		return errors.New("foundation create identity is invalid")
	}
	if identity.RetryToken != "" {
		token, err := hex.DecodeString(identity.RetryToken)
		if err != nil || len(token) != 32 {
			return errors.New("foundation create retry token is invalid")
		}
	}
	return nil
}

// OriginalStartupResources is independently observed DATA, never startup authority.
// Bootstrap retains its own private provenance after verifying the signed recipe.
type OriginalStartupResources struct {
	ResourceIDs                                                                        map[string]string
	ActorOperationID, InstanceOCID, EvidenceSHA256                                     string
	Create                                                                             CreateIdentity
	SourceObject, SourceSecretName, ProducerIntentSHA256, AdmissionAuthorizationSHA256 string
	Scope                                                                              jsontext.Value
	LaunchRequest                                                                      []byte
	PublicationScope                                                                   jsontext.Value
	ExpiresAt                                                                          time.Time
}

// ResolveOriginalStartup reads only the original protected GRU record and the
// selected region's exact retained resources. Observed names never create birth.
func ResolveOriginalStartup(ctx context.Context, factory *ociclient.Factory, authority Authority, grantWire []byte, anchorExpires time.Time) (OriginalStartupResources, error) {
	deny := func() (OriginalStartupResources, error) {
		return OriginalStartupResources{}, errors.New("original startup protected birth is incomplete or differs from signed scope")
	}
	if factory == nil || ctx == nil || ctx.Err() != nil || !catalog.IsCell(authority.Cell) || !entityid.Valid(authority.InstallationID) || authority.Generation != 1 || !canonicalDigest(authority.GrantSHA256) || digest(grantWire) != authority.GrantSHA256 || authority.Scope.Domain != "terrascale.foundation.scope" || authority.Scope.Cell != "GRU" || authority.Scope.Role != "foundation" || !time.Now().Before(anchorExpires) {
		return deny()
	}
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy != authority.TenancyID {
		return deny()
	}
	envelope, err := trust.DecodeEnvelope(grantWire)
	if err != nil {
		return deny()
	}
	payload, err := trust.VerifyCurrent(envelope, authority.Scope, authority.Roots, time.Now(), authority.Policy)
	if err != nil || envelope.ExpiresAt.After(anchorExpires) {
		return deny()
	}
	if err := verifyCurrentGrant(ctx, factory, authority, grantWire); err != nil {
		return OriginalStartupResources{}, err
	}
	var grant map[string]any
	if json.Unmarshal(payload, &grant) != nil || originalNumber(grant, "schemaVersion") != 3 || originalNumber(grant, "generation") != 1 || originalText(grant, "tenancyId") != tenancy || originalText(grant, "installationId") != authority.InstallationID {
		return deny()
	}
	regions, ok := grant["regions"].([]any)
	if !ok || len(regions) != 3 {
		return deny()
	}
	var selected map[string]any
	seen := map[string]bool{}
	for _, raw := range regions {
		regional, ok := raw.(map[string]any)
		if !ok {
			return deny()
		}
		plan := originalMap(regional, "plan")
		cell := originalText(plan, "cell")
		if !catalog.IsCell(cell) || seen[cell] || originalNumber(regional, "generation") != 1 || originalText(plan, "region") != catalog.OCIRegion(cell) {
			return deny()
		}
		seen[cell] = true
		if cell == authority.Cell {
			selected = regional
		}
	}
	if selected == nil {
		return deny()
	}
	material := originalMap(selected, "bootstrapMaterial")
	purpose := originalMap(material, "originalSourceProducer")
	admission := originalMap(material, "originalStartupAdmission")
	startup := originalMap(material, "startup")
	if originalText(purpose, "purpose") != "original-source-archive/v1" || originalText(purpose, "cell") != authority.Cell || originalText(purpose, "installationId") != authority.InstallationID || originalText(purpose, "tenancyId") != tenancy || originalNumber(purpose, "generation") != 1 || originalText(purpose, "journalObject") != "orchestrator/regions/v1/GRU.json" || originalText(admission, "purpose") != "original-controller-startup/v1" || len(admission) != 3 || originalText(admission, "producerIntentSha256") != originalDigest(purpose) || originalText(admission, "ledgerRetentionRuleId") == "" || originalText(startup, "controllerConfigDerivation") != "terrascale.bootstrap.controller.v2" {
		return deny()
	}
	home := originalMap(purpose, "home")
	if originalText(home, "namespace") != authority.Namespace || originalText(home, "headBucket") != authority.Bucket || originalText(home, "prefix") != authority.Prefix {
		return deny()
	}
	iamRecipes, ok := grant["originalMaterialPublicationIam"].([]any)
	if !ok || len(iamRecipes) != 3 {
		return deny()
	}
	foundIAM := false
	for _, raw := range iamRecipes {
		recipe, ok := raw.(map[string]any)
		if !ok {
			return deny()
		}
		if originalText(recipe, "cell") == authority.Cell {
			if foundIAM || (originalText(recipe, "purpose") != "original-material-publication-iam/v3" && originalText(recipe, "purpose") != "original-material-publication-iam/v4") || originalText(recipe, "producerIntentSha256") != originalDigest(purpose) {
				return deny()
			}
			foundIAM = true
		}
	}
	if !foundIAM {
		return deny()
	}
	recordAuthority := authority
	recordAuthority.Cell = "GRU"
	current, err := loadOriginalRecord(ctx, factory, recordAuthority)
	if err != nil {
		return OriginalStartupResources{}, err
	}
	if current.SchemaVersion != 1 || current.Cell != "GRU" || current.Stage != "original-foundation" || current.TenancyID != tenancy || current.ParentCompartmentID != originalText(grant, "parentCompartmentId") || current.Generation != 1 || current.GrantSHA256 != authority.GrantSHA256 || current.BlockedReason != "" || current.OperationID != entityid.Derive("regional-foundation", tenancy, "GRU", "1") {
		return deny()
	}
	var root map[string]any
	var births []map[string]any
	if json.Unmarshal(current.OriginalFoundationCompartments, &root) != nil || json.Unmarshal(current.OriginalSourceProducers, &births) != nil || len(births) != 3 || originalText(root, "grantSha256") != authority.GrantSHA256 || originalNumber(root, "generation") != 1 || originalText(root, "operationId") != current.OperationID || originalText(root, "gruIntentSha256") != current.IntentDigest || !canonicalDigest(originalText(root, "bundleSha256")) {
		return deny()
	}
	rootRegions, ok := root["regions"].([]any)
	if !ok || len(rootRegions) != 3 {
		return deny()
	}
	index := slices.Index([]string{"GRU", "SJC", "FRA"}, authority.Cell)
	regional, ok := rootRegions[index].(map[string]any)
	if !ok || originalText(regional, "cell") != authority.Cell || originalText(regional, "ociRegion") != catalog.OCIRegion(authority.Cell) || originalNumber(regional, "generation") != 1 {
		return deny()
	}
	birth := births[index]
	if originalDigest(originalMap(birth, "intent")) != originalDigest(purpose) || originalText(birth, "intentSha256") != originalDigest(purpose) || originalText(birth, "originalGrantSha256") != authority.GrantSHA256 || originalText(birth, "originalBundleSha256") != originalText(root, "bundleSha256") || originalText(birth, "originalOperationId") != current.OperationID || originalText(birth, "originalGruIntentSha256") != current.IntentDigest || originalText(birth, "bornAt") == "" || originalText(birth, "bornAt") != originalText(root, "bornAt") || originalText(regional, "producerIntentSha256") != originalDigest(purpose) || originalText(regional, "intentSha256") != originalDigest(selected) {
		return deny()
	}
	ids := map[string]string{}
	compartments, ok := regional["compartments"].([]any)
	if !ok || len(compartments) != 2 {
		return deny()
	}
	for i, role := range []string{"control_compartment", "network_compartment"} {
		entry, ok := compartments[i].(map[string]any)
		if !ok || originalText(entry, "role") != role {
			return deny()
		}
		selectedID := originalText(entry, "selectedId")
		if selectedID != "" {
			signedIDs := originalMap(originalMap(selected, "plan"), "resource_ids")
			if originalText(signedIDs, role) != selectedID || originalMap(entry, "pending") != nil || originalMap(entry, "provenance") != nil || originalText(entry, "holdReason") != "" || originalText(entry, "verifiedAt") == "" || !canonicalDigest(originalText(entry, "readbackSha256")) || authority.Cell == "GRU" && role == "control_compartment" && selectedID != originalText(originalMap(purpose, "escrow"), "compartmentOcid") {
				return deny()
			}
			ids[role] = selectedID
			continue
		}
		id, err := originalResourceBirth(entry, role, regional, authority.GrantSHA256)
		if err != nil {
			return deny()
		}
		ids[role] = id
	}
	network := originalMap(regional, "network")
	if network["complete"] != true || originalText(network, "compartmentId") != ids["network_compartment"] {
		return deny()
	}
	creates, ok := network["creates"].([]any)
	if !ok || len(creates) != 6 {
		return deny()
	}
	for _, raw := range creates {
		entry, ok := raw.(map[string]any)
		if !ok {
			return deny()
		}
		key := originalText(entry, "key")
		id, err := originalResourceBirth(entry, key, regional, authority.GrantSHA256)
		if err != nil {
			return deny()
		}
		if key == "controller_nsg" {
			key = "network_security_group"
		}
		ids[key] = id
	}
	vault := originalMap(regional, "vault")
	if originalText(vault, "controlCompartmentId") != ids["control_compartment"] {
		return deny()
	}
	escrow := originalMap(material, "sourceVaultTarget")
	for key, signed := range map[string]string{"vault": originalText(escrow, "vaultOcid"), "key": originalText(escrow, "kmsKeyOcid")} {
		entry := originalMap(vault, key)
		if selected := originalText(entry, "selectedId"); selected != "" && entry["provenance"] == nil && entry["pending"] == nil {
			// The home Vault/key is the signed escrow prerequisite, selected rather than born.
			if selected != signed || originalText(vault, "controlCompartmentId") != originalText(escrow, "compartmentOcid") || originalText(entry, "holdReason") != "" || originalText(entry, "verifiedAt") == "" || !canonicalDigest(originalText(entry, "readbackSha256")) {
				return deny()
			}
			ids[key] = selected
			continue
		}
		id, err := originalResourceBirth(entry, key, regional, authority.GrantSHA256)
		if err != nil {
			return deny()
		}
		ids[key] = id
	}
	actor := originalMap(regional, "actor")
	actorProof := originalMap(actor, "provenance")
	pending := originalMap(actor, "pending")
	request := originalMap(actor, "request")
	create := originalMap(pending, "request")
	var createIdentity CreateIdentity
	createWire, _ := json.Marshal(create, json.Deterministic(true))
	if json.Unmarshal(createWire, &createIdentity, json.RejectUnknownMembers(true)) != nil || createIdentity.Validate() != nil || !canonicalDigest(createIdentity.RequestDigest) || !canonicalDigest(createIdentity.RetryToken) || createIdentity.Key != "controller-a" || createIdentity.Region != catalog.OCIRegion(authority.Cell) || createIdentity.RequestDigest != originalLaunchDigest(request) || originalText(pending, "operationId") != originalText(purpose, "operationId") || !entityid.Valid(originalText(purpose, "operationId")) || originalText(pending, "intentDigest") != originalText(regional, "intentSha256") || originalDigest(originalMap(actorProof, "create")) != originalDigest(pending) || originalText(actorProof, "grantSha256") != authority.GrantSHA256 || originalNumber(actorProof, "generation") != 1 || originalText(actor, "holdReason") != "" || originalText(actor, "verifiedAt") == "" || !canonicalDigest(originalText(actor, "readbackSha256")) {
		return deny()
	}
	retry := sha256.Sum256([]byte("foundation-host-request:" + originalText(purpose, "operationId") + ":" + createIdentity.RequestDigest))
	if createIdentity.RetryToken != hex.EncodeToString(retry[:]) {
		return deny()
	}
	actorID := originalText(actorProof, "resourceId")
	if !resourceID(actorID, "instance", createIdentity.Region) || originalDigest(originalMap(actor, "startup")) != originalDigest(startup) || originalDigest(originalMap(actor, "config")) != originalDigest(originalMap(material, "config")) || originalText(purpose, "planSha256") != originalText(material, "planSha256") {
		return deny()
	}
	var launch core.LaunchInstanceDetails
	requestWire, _ := json.Marshal(request, json.Deterministic(true))
	if json.Unmarshal(requestWire, &launch) != nil || value(launch.CompartmentId) != ids["control_compartment"] || launch.CreateVnicDetails == nil || value(launch.CreateVnicDetails.SubnetId) != ids["subnet"] || !slices.Equal(launch.CreateVnicDetails.NsgIds, []string{ids["network_security_group"]}) || launch.ShapeConfig == nil || launch.ShapeConfig.Ocpus == nil || launch.ShapeConfig.MemoryInGBs == nil {
		return deny()
	}
	var metadata struct {
		SchemaVersion        int    `json:"schemaVersion"`
		Slot                 string `json:"slot"`
		OriginalBundleSHA256 string `json:"originalBundleSha256"`
	}
	if len(launch.Metadata) != 1 || json.Unmarshal([]byte(launch.Metadata["terrascale-bootstrap"]), &metadata, json.RejectUnknownMembers(true)) != nil || metadata.SchemaVersion != 1 || metadata.Slot != "controller-a" || metadata.OriginalBundleSHA256 != originalText(root, "bundleSha256") {
		return deny()
	}
	observed := current
	observed.OCIRegion = createIdentity.Region
	observed.ResourceIDs = maps.Clone(ids)
	if err := observe(ctx, factory, originalMap(selected, "plan"), observed); err != nil {
		return OriginalStartupResources{}, err
	}
	regionalClient, err := factory.ForRegion(createIdentity.Region)
	if err != nil {
		return OriginalStartupResources{}, err
	}
	if err := observeOriginalActor(ctx, regionalClient, actor, launch, actorID, ids["network_compartment"]); err != nil {
		return OriginalStartupResources{}, err
	}
	deadline := envelope.ExpiresAt
	if anchorExpires.Before(deadline) {
		deadline = anchorExpires
	}
	launchDeadline, err := time.Parse(time.RFC3339Nano, originalText(purpose, "launchDeadline"))
	if err != nil {
		return deny()
	}
	if launchDeadline.Before(deadline) {
		deadline = launchDeadline
	}
	imageWire, err := json.Marshal(startup["releaseImageReceiptWire"])
	if err != nil {
		return deny()
	}
	var signedImage []byte
	if json.Unmarshal(imageWire, &signedImage) != nil {
		return deny()
	}
	imageEnvelope, err := trust.DecodeEnvelope(signedImage)
	if err != nil {
		return deny()
	}
	if imageEnvelope.ExpiresAt.Before(deadline) {
		deadline = imageEnvelope.ExpiresAt
	}
	if !time.Now().Before(deadline) {
		return deny()
	}
	for _, key := range []string{"sourceIam", "admissionReads", "materialPublicationIam"} {
		entry := originalMap(regional, key)
		if entry == nil || originalText(entry, "holdReason") != "" || originalText(entry, "verifiedAt") == "" || !canonicalDigest(originalText(entry, "readbackSha256")) || originalMap(entry, "provenance") == nil {
			return deny()
		}
		if err := observeOriginalPolicy(ctx, factory, entry, key == "materialPublicationIam"); err != nil {
			return OriginalStartupResources{}, err
		}
	}
	publicationScope, err := verifyOriginalMaterialScope(ctx, factory, authority, root, regional, birth, selected, iamRecipes, ids)
	if err != nil {
		return OriginalStartupResources{}, err
	}
	publication := originalMap(root, "publication")
	if publication == nil || publication["readbacks"] == nil {
		return deny()
	}
	scope := map[string]any{"SHA256": "", "InstanceID": actorID, "Cell": authority.Cell, "InstallationID": authority.InstallationID, "Generation": authority.Generation, "GrantSHA256": authority.GrantSHA256, "BundleSHA256": originalText(root, "bundleSha256"), "BirthSHA256": originalDigest(birth), "ActorRequestSHA256": createIdentity.RequestDigest, "ActorReadbackSHA256": originalText(actor, "readbackSha256"), "SourceIAMSHA256": originalDigest(originalMap(regional, "sourceIam")), "AdmissionReadsSHA256": originalDigest(originalMap(regional, "admissionReads")), "PublicationSHA256": originalDigest(publication), "PlanSHA256": originalText(material, "planSha256"), "TemplateSHA256": originalDigest(startup), "Deadline": deadline}
	scope["SHA256"] = originalDigest(scope)
	scopeWire, _ := json.Marshal(scope, json.Deterministic(true))
	evidence := originalDigest(struct {
		Grant        string
		Installation string
		Generation   uint64
		Cell         string
		Birth        map[string]any
		Actor        map[string]any
	}{authority.GrantSHA256, authority.InstallationID, authority.Generation, authority.Cell, birth, actor})
	return OriginalStartupResources{ResourceIDs: ids, ActorOperationID: originalText(purpose, "operationId"), InstanceOCID: actorID, Create: createIdentity, EvidenceSHA256: evidence, SourceObject: originalText(purpose, "sourceObject"), SourceSecretName: originalText(purpose, "sourceSecretName"), ProducerIntentSHA256: originalDigest(purpose), AdmissionAuthorizationSHA256: originalText(purpose, "admissionAuthorizationSha256"), Scope: scopeWire, LaunchRequest: requestWire, PublicationScope: publicationScope, ExpiresAt: deadline}, ctx.Err()
}

func originalResourceBirth(entry map[string]any, key string, regional map[string]any, grantSHA string) (string, error) {
	proof := originalMap(entry, "provenance")
	birth := originalMap(proof, "create")
	request := originalMap(birth, "request")
	selected := originalText(entry, "selectedId")
	if proof == nil && selected != "" {
		return "", errors.New("selected original resources require protected birth")
	}
	if proof == nil || originalText(entry, "holdReason") != "" || originalText(entry, "verifiedAt") == "" || !canonicalDigest(originalText(entry, "readbackSha256")) || originalText(proof, "grantSha256") != grantSHA || originalNumber(proof, "generation") != 1 || originalText(birth, "operationId") != originalText(regional, "operationId") || originalText(birth, "intentDigest") != originalText(regional, "intentSha256") || originalText(request, "key") != key || !canonicalDigest(originalText(request, "requestDigest")) || originalText(birth, "firstAttemptAt") == "" {
		return "", errors.New("original resource lacks immutable create identity")
	}
	id := originalText(proof, "resourceId")
	if id == "" || selected != "" && selected != id {
		return "", errors.New("original resource ID differs from birth")
	}
	return id, nil
}

func observeOriginalActor(ctx context.Context, regional *ociclient.Factory, actor map[string]any, request core.LaunchInstanceDetails, id, networkCompartment string) error {
	deny := errors.New("original actor live metadata differs from retained create")
	compute, err := regional.Compute()
	if err != nil {
		return err
	}
	response, err := compute.GetInstance(ociclient.RequestContext(ctx), core.GetInstanceRequest{InstanceId: new(id)})
	if err != nil {
		return err
	}
	i := response.Instance
	source, ok := i.SourceDetails.(core.InstanceSourceViaImageDetails)
	expected, expectedOK := request.SourceDetails.(core.InstanceSourceViaImageDetails)
	if !ok || !expectedOK || value(i.Id) != id || value(i.CompartmentId) != value(request.CompartmentId) || i.LifecycleState != core.InstanceLifecycleStateRunning || value(i.AvailabilityDomain) != value(request.AvailabilityDomain) || value(i.FaultDomain) != value(request.FaultDomain) || value(i.Shape) != value(request.Shape) || value(source.ImageId) != value(expected.ImageId) || value(i.ImageId) != value(expected.ImageId) || !maps.Equal(i.Metadata, request.Metadata) || len(i.ExtendedMetadata) != 0 || value(i.IpxeScript) != "" || i.ShapeConfig == nil || i.ShapeConfig.Ocpus == nil || i.ShapeConfig.MemoryInGBs == nil || *i.ShapeConfig.Ocpus != *request.ShapeConfig.Ocpus || *i.ShapeConfig.MemoryInGBs != *request.ShapeConfig.MemoryInGBs {
		return deny
	}
	if value(i.DisplayName) != value(request.DisplayName) {
		return deny
	}
	var attachments []core.VnicAttachment
	page := ""
	seen := map[string]bool{}
	for range 3 {
		if seen[page] || len(page) > 1024 {
			return deny
		}
		seen[page] = true
		query := core.ListVnicAttachmentsRequest{CompartmentId: request.CompartmentId, InstanceId: new(id), AvailabilityDomain: request.AvailabilityDomain, Limit: new(2)}
		if page != "" {
			query.Page = new(page)
		}
		response, err := compute.ListVnicAttachments(ociclient.RequestContext(ctx), query)
		if err != nil {
			return err
		}
		attachments = append(attachments, response.Items...)
		if len(attachments) > 1 {
			return deny
		}
		page = value(response.OpcNextPage)
		if page == "" {
			break
		}
	}
	if page != "" || len(attachments) != 1 {
		return deny
	}
	attachment := attachments[0]
	if value(attachment.InstanceId) != id || value(attachment.VnicId) != originalText(actor, "primaryVnicId") || value(attachment.CompartmentId) != value(request.CompartmentId) || value(attachment.AvailabilityDomain) != value(request.AvailabilityDomain) || value(attachment.SubnetId) != value(request.CreateVnicDetails.SubnetId) || attachment.LifecycleState != core.VnicAttachmentLifecycleStateAttached || value(attachment.VlanId) != "" {
		return deny
	}
	network, err := regional.Network()
	if err != nil {
		return err
	}
	vnic, err := network.GetVnic(ociclient.RequestContext(ctx), core.GetVnicRequest{VnicId: new(originalText(actor, "primaryVnicId"))})
	if err != nil {
		return err
	}
	actualNSGs := slices.Clone(vnic.NsgIds)
	wantNSGs := slices.Clone(request.CreateVnicDetails.NsgIds)
	slices.Sort(actualNSGs)
	slices.Sort(wantNSGs)
	if value(vnic.Id) != originalText(actor, "primaryVnicId") || vnic.LifecycleState != core.VnicLifecycleStateAvailable || vnic.IsPrimary == nil || !*vnic.IsPrimary || value(vnic.SubnetId) != value(request.CreateVnicDetails.SubnetId) || value(vnic.PrivateIp) != value(request.CreateVnicDetails.PrivateIp) || value(vnic.PublicIp) != "" || len(vnic.Ipv6Addresses) != 0 || !slices.Equal(actualNSGs, wantNSGs) {
		return deny
	}
	if value(vnic.CompartmentId) != networkCompartment || value(vnic.AvailabilityDomain) != value(request.AvailabilityDomain) || vnic.SkipSourceDestCheck == nil || *vnic.SkipSourceDestCheck || value(vnic.VlanId) != "" || value(vnic.RouteTableId) != "" {
		return deny
	}
	var bootAttachments []core.BootVolumeAttachment
	page = ""
	clear(seen)
	for range 3 {
		if seen[page] || len(page) > 1024 {
			return deny
		}
		seen[page] = true
		query := core.ListBootVolumeAttachmentsRequest{CompartmentId: request.CompartmentId, InstanceId: new(id), AvailabilityDomain: request.AvailabilityDomain, Limit: new(2)}
		if page != "" {
			query.Page = new(page)
		}
		response, err := compute.ListBootVolumeAttachments(ociclient.RequestContext(ctx), query)
		if err != nil {
			return err
		}
		bootAttachments = append(bootAttachments, response.Items...)
		if len(bootAttachments) > 1 {
			return deny
		}
		page = value(response.OpcNextPage)
		if page == "" {
			break
		}
	}
	if page != "" || len(bootAttachments) != 1 {
		return deny
	}
	bootAttachment := bootAttachments[0]
	if value(bootAttachment.InstanceId) != id || value(bootAttachment.BootVolumeId) != originalText(actor, "bootVolumeId") || value(bootAttachment.CompartmentId) != value(request.CompartmentId) || value(bootAttachment.AvailabilityDomain) != value(request.AvailabilityDomain) || bootAttachment.LifecycleState != core.BootVolumeAttachmentLifecycleStateAttached {
		return deny
	}
	volumes, err := regional.Blockstorage()
	if err != nil {
		return err
	}
	boot, err := volumes.GetBootVolume(ociclient.RequestContext(ctx), core.GetBootVolumeRequest{BootVolumeId: new(originalText(actor, "bootVolumeId"))})
	if err != nil {
		return err
	}
	if value(boot.Id) != originalText(actor, "bootVolumeId") || boot.LifecycleState != core.BootVolumeLifecycleStateAvailable || value(boot.CompartmentId) != value(request.CompartmentId) || value(boot.AvailabilityDomain) != value(request.AvailabilityDomain) || value(boot.ImageId) != value(expected.ImageId) || boot.SizeInGBs == nil || expected.BootVolumeSizeInGBs == nil || *boot.SizeInGBs != *expected.BootVolumeSizeInGBs || boot.VpusPerGB == nil || *boot.VpusPerGB != 10 {
		return deny
	}
	if boot.IsAutoTuneEnabled != nil && *boot.IsAutoTuneEnabled || len(boot.AutotunePolicies) != 0 || boot.AutoTunedVpusPerGB != nil && *boot.AutoTunedVpusPerGB != 10 {
		return deny
	}
	image, err := compute.GetImage(ociclient.RequestContext(ctx), core.GetImageRequest{ImageId: expected.ImageId})
	if err != nil {
		return err
	}
	if value(image.Id) != value(expected.ImageId) || image.LifecycleState != core.ImageLifecycleStateAvailable {
		return deny
	}
	return ctx.Err()
}

func originalMap(parent map[string]any, key string) map[string]any {
	v, _ := parent[key].(map[string]any)
	return v
}
func originalText(parent map[string]any, key string) string { v, _ := parent[key].(string); return v }
func originalNumber(parent map[string]any, key string) float64 {
	v, _ := parent[key].(float64)
	return v
}

// originalDigest hashes a value decoded from the wire (sorted keys) or a typed
// SDK value both sides encode the same way.
func originalDigest(value any) string {
	wire, err := json.Marshal(value, json.Deterministic(true))
	if err != nil {
		return ""
	}
	return digest(wire)
}

// originalCanonical compares a wire-decoded value with a typed expectation.
func originalCanonical(value any) string {
	sum, _ := CanonicalDigest(value)
	return sum
}

// CanonicalDigest is the one original-protocol digest: SHA-256 of the sorted-key
// JSON of the decoded value. A verifier recomputes it from the signed wire alone,
// without knowing Go struct field order. Options must match the encoding of the
// wire the value is read from (durable records encode nil maps and slices as null).
func CanonicalDigest(value any, options ...json.Options) (string, error) {
	wire, err := json.Marshal(value, append(options, json.Deterministic(true))...)
	if err != nil {
		return "", err
	}
	var decoded any
	if err := json.Unmarshal(wire, &decoded); err != nil {
		return "", err
	}
	wire, err = json.Marshal(decoded, json.Deterministic(true))
	if err != nil {
		return "", err
	}
	return digest(wire), nil
}

// Resolve checks only the finite IDs returned by independent verification.
// This DATA method is never accepted as a constructor for bootstrap authority.
func (resources OriginalStartupResources) Resolve(reference string) (string, error) {
	cell, key, err := Parse(reference)
	if err != nil || catalog.OCIRegion(cell) != resources.Create.Region || resources.ResourceIDs[key] == "" {
		return "", errors.New("original startup reference is outside the selected birth")
	}
	return resources.ResourceIDs[key], nil
}

func (resources OriginalStartupResources) MatchesScope(wire []byte) bool {
	var actual, want map[string]any
	// Producers encode their typed scope; content, not member order, is the identity.
	return json.Unmarshal(wire, &actual) == nil && json.Unmarshal(resources.Scope, &want) == nil && originalDigest(actual) == originalDigest(want)
}

type originalVaultTarget struct {
	CompartmentOCID string `json:"compartmentOcid"`
	VaultOCID       string `json:"vaultOcid"`
	KMSKeyOCID      string `json:"kmsKeyOcid"`
}
type originalIAMProducer struct {
	Cell         string `json:"cell"`
	DeploymentID string `json:"deploymentId"`
	ClusterID    string `json:"clusterId"`
	ImageOCID    string `json:"imageOcid"`
	SourceObject string `json:"sourceObject"`
	Home         struct {
		HeadBucket       string `json:"headBucket"`
		LedgerBucket     string `json:"ledgerBucket"`
		HeadKMSKeyOCID   string `json:"headKmsKeyOcid"`
		LedgerKMSKeyOCID string `json:"ledgerKmsKeyOcid"`
		Prefix           string `json:"prefix"`
	} `json:"home"`
	Escrow originalVaultTarget `json:"escrow"`
}
type originalIAMStatementsScope struct {
	Recipe struct {
		TenancyID             string `json:"tenancyId"`
		Cell                  string `json:"cell"`
		Purpose               string `json:"purpose"`
		RuntimeJoinSecretName string `json:"runtimeJoinSecretName"`
	} `json:"recipe"`
	ActorID          string `json:"actorId"`
	PeerDynamicGroup *struct {
		Request identity.CreateDynamicGroupDetails `json:"request"`
	} `json:"peerDynamicGroup"`
	Startup *struct {
		Producer                 originalIAMProducer `json:"producer"`
		HomeControlCompartmentID string              `json:"homeControlCompartmentId"`
		Regions                  []struct {
			Producer             originalIAMProducer `json:"producer"`
			Target               originalVaultTarget `json:"target"`
			NetworkCompartmentID string              `json:"networkCompartmentId"`
			ImageCompartmentID   string              `json:"imageCompartmentId"`
			SecretNames          []string            `json:"secretNames"`
			LinkSecretNames      [8]string           `json:"linkSecretNames"`
			LinkObject           string              `json:"linkObject"`
			LinkEscrowSecretName string              `json:"linkEscrowSecretName"`
		} `json:"regions"`
	} `json:"startup"`
}
type originalIAMOperation struct{ Operation, ResourceType, Permission, Scope string }

func originalStartupPublicationOperations() [7]originalIAMOperation {
	return [7]originalIAMOperation{
		{"ListSecrets", "secrets", "SECRET_INSPECT", "regional-control-list"}, {"CreateSecret", "secrets", "SECRET_CREATE", "material-names-vault"}, {"GetSecret", "secrets", "SECRET_READ", "material-names-vault"}, {"GetSecretBundle", "secret-bundles", "SECRET_BUNDLE_READ", "material-names-vault"}, {"CreateSecret", "vaults", "VAULT_CREATE_SECRET", "material-vault"}, {"CreateSecret", "keys", "KEY_ENCRYPT", "material-key"}, {"CreateSecret", "keys", "KEY_DECRYPT", "material-key"},
	}
}

// OriginalMaterialIAMIdentity digests a retained material IAM entry without its
// effect state; the producer and every verifier share this one definition.
func OriginalMaterialIAMIdentity(entry map[string]any) string {
	identityScope := maps.Clone(entry)
	for _, key := range []string{"pending", "provenance", "policyEtag", "readbackSha256", "verifiedAt", "holdReason", "peerDynamicGroup"} {
		delete(identityScope, key)
	}
	identityScope["identitySha256"] = ""
	identityScope["request"] = identity.CreatePolicyDetails{}
	return originalDigest(identityScope)
}

// originalVaultResourceID is the born ID, or the selected home prerequisite ID.
func originalVaultResourceID(entry map[string]any) string {
	if id := originalText(originalMap(entry, "provenance"), "resourceId"); id != "" {
		return id
	}
	return originalText(entry, "selectedId")
}

// originalLaunchDigest matches the dispatched create identity: the SDK wire body
// of the retained launch details, digested canonically.
func originalLaunchDigest(request map[string]any) string {
	var launch core.LaunchInstanceDetails
	wire, err := json.Marshal(request, json.Deterministic(true))
	if err != nil || json.Unmarshal(wire, &launch) != nil {
		return ""
	}
	httpRequest, err := (core.LaunchInstanceRequest{LaunchInstanceDetails: launch}).HTTPRequest(http.MethodPost, "/20160918/instances", nil, nil)
	if err != nil || httpRequest.Body == nil {
		return ""
	}
	defer httpRequest.Body.Close()
	body, err := io.ReadAll(io.LimitReader(httpRequest.Body, recordLimit+1))
	var object any
	if err != nil || len(body) > recordLimit || json.Unmarshal(body, &object) != nil {
		return ""
	}
	return originalDigest(object)
}

func originalPolicyBody(request identity.CreatePolicyDetails) ([]byte, error) {
	httpRequest, err := (identity.CreatePolicyRequest{CreatePolicyDetails: request}).HTTPRequest(http.MethodPost, "/20160918/policies", nil, nil)
	if err != nil {
		return nil, err
	}
	if httpRequest.Body == nil {
		return nil, errors.New("original policy SDK request has no body")
	}
	defer httpRequest.Body.Close()
	wire, err := io.ReadAll(io.LimitReader(httpRequest.Body, recordLimit+1))
	if err != nil || len(wire) > recordLimit {
		return nil, errors.New("original policy exceeds bound")
	}
	var body map[string]any
	if json.Unmarshal(wire, &body) != nil {
		return nil, errors.New("original policy body is invalid")
	}
	return json.Marshal(body, json.Deterministic(true))
}

func loadOriginalRecord(ctx context.Context, factory *ociclient.Factory, authority Authority) (record, error) {
	home, err := factory.ForRegion("sa-saopaulo-1")
	if err != nil {
		return record{}, err
	}
	objects, err := home.ObjectStorage()
	if err != nil {
		return record{}, err
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	response, err := objects.GetObject(ociclient.RequestContext(bounded), objectstorage.GetObjectRequest{NamespaceName: new(authority.Namespace), BucketName: new(authority.Bucket), ObjectName: new("orchestrator/regions/v1/GRU.json")})
	if err != nil {
		return record{}, err
	}
	if response.Content == nil {
		return record{}, errors.New("original journal has no content")
	}
	defer response.Content.Close()
	// Original all-region journals already use the producer's 512 KiB bound.
	const originalJournalLimit = 512 << 10
	wire, err := io.ReadAll(io.LimitReader(response.Content, originalJournalLimit+1))
	if err != nil || len(wire) > originalJournalLimit || response.ETag == nil || *response.ETag == "" {
		return record{}, errors.New("original journal exceeds its protected bound or lacks revision")
	}
	var current record
	if err := json.Unmarshal(wire, &current, json.RejectUnknownMembers(true)); err != nil {
		return record{}, err
	}
	return current, nil
}

func observeOriginalPolicy(ctx context.Context, factory *ociclient.Factory, entry map[string]any, pinnedETag bool) error {
	deny := errors.New("original current IAM policy differs from protected exact request")
	home, err := factory.ForRegion("sa-saopaulo-1")
	if err != nil {
		return err
	}
	iam, err := home.Identity()
	if err != nil {
		return err
	}
	var request identity.CreatePolicyDetails
	wire, _ := json.Marshal(entry["request"], json.Deterministic(true))
	if json.Unmarshal(wire, &request) != nil {
		return deny
	}
	proof := originalMap(entry, "provenance")
	id := originalText(proof, "resourceId")
	if !resourceID(id, "policy", "") {
		return deny
	}
	body, err := originalPolicyBody(request)
	if err != nil {
		return err
	}
	pending := originalMap(entry, "pending")
	if originalDigest(originalMap(proof, "create")) != originalDigest(pending) || originalText(originalMap(pending, "request"), "requestDigest") != digest(body) || originalText(proof, "grantSha256") != originalText(entry, "grantSha256") || originalNumber(proof, "generation") != originalNumber(entry, "generation") {
		return deny
	}
	response, err := iam.GetPolicy(ociclient.RequestContext(ctx), identity.GetPolicyRequest{PolicyId: new(id)})
	if err != nil {
		return err
	}
	if value(response.Id) != id || value(response.CompartmentId) != value(request.CompartmentId) || value(response.Name) != value(request.Name) || value(response.Description) != value(request.Description) || response.LifecycleState != identity.PolicyLifecycleStateActive || !slices.Equal(response.Statements, request.Statements) || originalDigest(response.VersionDate) != originalDigest(request.VersionDate) || originalDigest(response.FreeformTags) != originalDigest(request.FreeformTags) || originalDigest(response.DefinedTags) != originalDigest(request.DefinedTags) || pinnedETag && (originalText(entry, "policyEtag") == "" || value(response.Etag) != originalText(entry, "policyEtag")) {
		return deny
	}
	return ctx.Err()
}

func verifyOriginalMaterialScope(ctx context.Context, factory *ociclient.Factory, authority Authority, root, regional, birth, selected map[string]any, recipes []any, ids map[string]string) (jsontext.Value, error) {
	deny := func() (jsontext.Value, error) {
		return nil, errors.New("original material IAMv3 differs from signed finite purpose")
	}
	entry := originalMap(regional, "materialPublicationIam")
	var recipe map[string]any
	for _, raw := range recipes {
		candidate, ok := raw.(map[string]any)
		if !ok {
			return deny()
		}
		if originalText(candidate, "cell") == authority.Cell {
			if recipe != nil {
				return deny()
			}
			recipe = candidate
		}
	}
	if recipe == nil || originalDigest(entry["recipe"]) != originalDigest(recipe) || (originalText(recipe, "purpose") != "original-material-publication-iam/v3" && originalText(recipe, "purpose") != "original-material-publication-iam/v4") || originalText(entry, "grantSha256") != authority.GrantSHA256 || originalText(entry, "bundleSha256") != originalText(root, "bundleSha256") || originalText(entry, "intentSha256") != originalText(regional, "intentSha256") || originalText(entry, "operationId") != originalText(regional, "operationId") || originalNumber(entry, "generation") != 1 || originalText(entry, "actorId") != originalText(originalMap(originalMap(regional, "actor"), "provenance"), "resourceId") || originalText(originalMap(originalMap(regional, "admissionReads"), "recipe"), "purpose") != "original-actor-admission-reads/v2" {
		return deny()
	}
	for key, value := range map[string]any{"birthSha256": birth, "actorSha256": regional["actor"], "vaultSha256": regional["vault"], "admissionSha256": regional["admissionReads"], "publicationSha256": root["publication"]} {
		if originalText(entry, key) != originalDigest(value) {
			return deny()
		}
	}
	target := map[string]any{"compartmentOcid": ids["control_compartment"], "vaultOcid": ids["vault"], "kmsKeyOcid": ids["key"]}
	if originalDigest(entry["target"]) != originalDigest(target) {
		return deny()
	}
	if originalText(recipe, "purpose") == "original-material-publication-iam/v4" {
		producer := originalMap(birth, "intent")
		clusterID := originalText(producer, "clusterId")
		name := vaultsecret.Name(strings.ToLower(authority.Cell)+"-"+strings.ToLower(clusterID), "TS_ORCHESTRATOR_SWARM_JOIN")
		if clusterID == "" || originalText(recipe, "runtimeJoinSecretName") != name {
			return deny()
		}
	} else if originalText(recipe, "runtimeJoinSecretName") != "" {
		return deny()
	}
	startup := originalMap(entry, "startup")
	roots, ok := root["regions"].([]any)
	if !ok || len(roots) != 3 || originalDigest(startup["producer"]) != originalDigest(birth["intent"]) || originalText(startup, "networkCompartmentId") != ids["network_compartment"] {
		return deny()
	}
	homeRegional, ok := roots[0].(map[string]any)
	if !ok || originalText(startup, "homeControlCompartmentId") != originalText(originalMap(homeRegional, "vault"), "controlCompartmentId") {
		return deny()
	}
	peerScopes, ok := startup["regions"].([]any)
	if !ok || len(peerScopes) != 3 {
		return deny()
	}
	for i, raw := range peerScopes {
		peer, ok := raw.(map[string]any)
		if !ok {
			return deny()
		}
		actual, ok := roots[i].(map[string]any)
		if !ok {
			return deny()
		}
		cell := []string{"GRU", "SJC", "FRA"}[i]
		var signed map[string]any
		for _, rawRecipe := range recipes {
			item, _ := rawRecipe.(map[string]any)
			if originalText(item, "cell") == cell {
				if signed != nil {
					return deny()
				}
				signed = item
			}
		}
		if signed == nil {
			return deny()
		}
		actor := originalMap(actual, "actor")
		vault := originalMap(actual, "vault")
		network := originalMap(actual, "network")
		founder := originalMap(originalMap(actor, "startup"), "founderResources")
		slots, ok := founder["slots"].([]any)
		if !ok || len(slots) != 3 {
			return deny()
		}
		slot, ok := slots[0].(map[string]any)
		if !ok {
			return deny()
		}
		actualTarget := map[string]any{"compartmentOcid": originalText(vault, "controlCompartmentId"), "vaultOcid": originalVaultResourceID(originalMap(vault, "vault")), "kmsKeyOcid": originalVaultResourceID(originalMap(vault, "key"))}
		producer := originalMap(peer, "producer")
		if originalText(producer, "cell") != cell || originalDigest(producer) != originalText(signed, "producerIntentSha256") || originalDigest(peer["target"]) != originalDigest(actualTarget) || originalText(peer, "networkCompartmentId") != originalText(network, "compartmentId") || originalText(peer, "imageCompartmentId") != originalText(slot, "imageCompartmentOcid") || originalDigest(peer["secretNames"]) != originalDigest(signed["secretNames"]) || originalDigest(peer["linkSecretNames"]) != originalDigest(signed["linkSecretNames"]) || originalText(peer, "linkObject") != originalText(signed, "linkObject") || originalText(peer, "linkEscrowSecretName") != originalText(signed, "linkEscrowSecretName") {
			return deny()
		}
	}
	identitySHA := OriginalMaterialIAMIdentity(entry)
	if !canonicalDigest(identitySHA) || originalText(entry, "identitySha256") != identitySHA {
		return deny()
	}
	group := originalMap(entry, "peerDynamicGroup")
	var groupRequest identity.CreateDynamicGroupDetails
	groupWire, _ := json.Marshal(group["request"], json.Deterministic(true))
	if json.Unmarshal(groupWire, &groupRequest) != nil {
		return deny()
	}
	expectedGroup := identity.CreateDynamicGroupDetails{CompartmentId: new(authority.TenancyID), Name: new("ts-original-peer-" + identitySHA[:32]), Description: new("Original regional controllers admitted by exact control compartment"), MatchingRule: new(fmt.Sprintf("ALL {instance.compartment.id='%s'}", ids["control_compartment"])), FreeformTags: map[string]string{}, DefinedTags: map[string]map[string]any{}}
	if originalDigest(groupRequest) != originalDigest(expectedGroup) || originalText(group, "holdReason") != "" || originalText(group, "verifiedAt") == "" || originalText(group, "etag") == "" || !canonicalDigest(originalText(group, "readbackSha256")) {
		return deny()
	}
	entryWire, _ := json.Marshal(entry, json.Deterministic(true))
	statements, err := OriginalStartupIAMStatements(entryWire)
	if err != nil {
		return nil, err
	}
	expectedPolicy := identity.CreatePolicyDetails{CompartmentId: new(authority.TenancyID), Name: new("ts-original-material-iam-" + identitySHA[:32]), Description: new("Prospectively authorized finite original startup and material publication"), Statements: statements, FreeformTags: map[string]string{}, DefinedTags: map[string]map[string]any{}}
	if wire, want := originalCanonical(entry["request"]), originalCanonical(expectedPolicy); wire == "" || wire != want {
		return deny()
	}
	home, err := factory.ForRegion("sa-saopaulo-1")
	if err != nil {
		return nil, err
	}
	iam, err := home.Identity()
	if err != nil {
		return nil, err
	}
	groupID := originalText(originalMap(group, "provenance"), "resourceId")
	if !resourceID(groupID, "dynamicgroup", "") {
		return deny()
	}
	response, err := iam.GetDynamicGroup(ociclient.RequestContext(ctx), identity.GetDynamicGroupRequest{DynamicGroupId: new(groupID)})
	if err != nil {
		return nil, err
	}
	if value(response.Id) != groupID || value(response.CompartmentId) != value(groupRequest.CompartmentId) || value(response.Name) != value(groupRequest.Name) || value(response.Description) != value(groupRequest.Description) || value(response.MatchingRule) != value(groupRequest.MatchingRule) || response.LifecycleState != identity.DynamicGroupLifecycleStateActive || value(response.Etag) != originalText(group, "etag") || originalDigest(response.FreeformTags) != originalDigest(groupRequest.FreeformTags) || originalDigest(response.DefinedTags) != originalDigest(groupRequest.DefinedTags) {
		return deny()
	}
	proof := originalMap(group, "provenance")
	pending := originalMap(group, "pending")
	request := originalMap(pending, "request")
	if originalDigest(proof["create"]) != originalDigest(pending) || originalText(proof, "grantSha256") != authority.GrantSHA256 || originalNumber(proof, "generation") != 1 || originalText(request, "requestDigest") != originalDigest(groupRequest) || originalText(group, "readbackSha256") != originalDigest([]string{groupID, originalDigest(groupRequest), originalText(group, "etag"), "ACTIVE"}) {
		return deny()
	}
	body, err := originalPolicyBody(expectedPolicy)
	if err != nil {
		return nil, err
	}
	policyID := originalText(originalMap(entry, "provenance"), "resourceId")
	if originalText(entry, "readbackSha256") != originalDigest([]string{policyID, digest(body), originalText(entry, "policyEtag"), "ACTIVE"}) {
		return deny()
	}
	scope := map[string]any{"target": target, "policyId": policyID, "policyEtag": originalText(entry, "policyEtag"), "policySha256": digest(body), "readbackSha256": originalText(entry, "readbackSha256")}
	wire, err := json.Marshal(scope, json.Deterministic(true))
	return wire, err
}

// OriginalStartupIAMStatements renders public DATA only, shared by the original
// producer and independent consumer; it confers no IAM or startup capability.
func OriginalStartupIAMStatements(scopeWire []byte) ([]string, error) {
	var scope originalIAMStatementsScope
	if json.Unmarshal(scopeWire, &scope) != nil || scope.Startup == nil || scope.PeerDynamicGroup == nil || len(scope.Startup.Regions) != 3 || scope.PeerDynamicGroup.Request.Name == nil || scope.Recipe.TenancyID == "" || !catalog.IsCell(scope.Recipe.Cell) || scope.ActorID == "" {
		return nil, errors.New("original startup IAM DATA is incomplete")
	}
	startup := scope.Startup
	if scope.Recipe.Purpose == "original-material-publication-iam/v4" {
		name := vaultsecret.Name(strings.ToLower(startup.Producer.Cell)+"-"+strings.ToLower(startup.Producer.ClusterID), "TS_ORCHESTRATOR_SWARM_JOIN")
		if startup.Producer.ClusterID == "" || startup.Producer.Cell != scope.Recipe.Cell || scope.Recipe.RuntimeJoinSecretName != name {
			return nil, errors.New("original startup IAM runtime join name differs from signed producer")
		}
	} else if scope.Recipe.RuntimeJoinSecretName != "" {
		return nil, errors.New("historical original startup IAM cannot acquire runtime join publication")
	}
	const actor = "any-user"
	peer := "dynamic-group " + value(scope.PeerDynamicGroup.Request.Name)
	type statementKey struct{ principal, compartment, verb, resource string }
	groups := map[statementKey][]string{}
	var order []statementKey
	add := func(principal, compartment, verb, resource, operation, permission, extra string) {
		if resource == "secrets" || resource == "keys" {
			verb = "manage"
		}
		key := statementKey{principal, compartment, verb, resource}
		if groups[key] == nil {
			order = append(order, key)
		}
		conditions := fmt.Sprintf("request.operation='%s'", operation)
		if permission != "" {
			conditions += fmt.Sprintf(", request.permission='%s'", permission)
		}
		if extra != "" {
			conditions += ", " + extra
		}
		term := "all {" + conditions + "}"
		if !slices.Contains(groups[key], term) {
			groups[key] = append(groups[key], term)
		}
	}
	// Each branch retains its operation, permission and exact resource selector together.
	read := func(principal, compartment, operation, permission, extra string) {
		add(principal, compartment, "read", "all-resources", operation, permission, extra)
	}
	for _, op := range [][2]string{{"GetPolicy", "POLICY_READ"}, {"GetDynamicGroup", "DYNAMIC_GROUP_INSPECT"}, {"GetCompartment", "COMPARTMENT_INSPECT"}, {"GetNamespace", "OBJECTSTORAGE_NAMESPACE_READ"}} {
		read(peer, scope.Recipe.TenancyID, op[0], op[1], "")
		if scope.Recipe.Cell == "GRU" {
			read(actor, scope.Recipe.TenancyID, op[0], op[1], "")
		}
	}
	for _, bucket := range []string{startup.Producer.Home.HeadBucket, startup.Producer.Home.LedgerBucket} {
		read(peer, startup.HomeControlCompartmentID, "GetBucket", "BUCKET_READ", fmt.Sprintf("target.bucket.name='%s'", bucket))
		if scope.Recipe.Cell == "GRU" {
			read(actor, startup.HomeControlCompartmentID, "GetBucket", "BUCKET_READ", fmt.Sprintf("target.bucket.name='%s'", bucket))
		}
	}
	for _, operation := range []string{"GetRetentionRule"} {
		read(peer, startup.HomeControlCompartmentID, operation, "BUCKET_READ", fmt.Sprintf("target.bucket.name='%s'", startup.Producer.Home.LedgerBucket))
		if scope.Recipe.Cell == "GRU" {
			read(actor, startup.HomeControlCompartmentID, operation, "BUCKET_READ", fmt.Sprintf("target.bucket.name='%s'", startup.Producer.Home.LedgerBucket))
		}
	}
	read(peer, startup.HomeControlCompartmentID, "GetVault", "VAULT_READ", fmt.Sprintf("target.vault.id='%s'", startup.Producer.Escrow.VaultOCID))
	if scope.Recipe.Cell == "GRU" {
		read(actor, startup.HomeControlCompartmentID, "GetVault", "VAULT_READ", fmt.Sprintf("target.vault.id='%s'", startup.Producer.Escrow.VaultOCID))
	}
	for _, key := range []string{startup.Producer.Home.HeadKMSKeyOCID, startup.Producer.Home.LedgerKMSKeyOCID} {
		read(peer, startup.HomeControlCompartmentID, "GetKey", "KEY_READ", fmt.Sprintf("target.key.id='%s'", key))
		if scope.Recipe.Cell == "GRU" {
			read(actor, startup.HomeControlCompartmentID, "GetKey", "KEY_READ", fmt.Sprintf("target.key.id='%s'", key))
		}
	}
	publish := func(target originalVaultTarget, names []string, bundleOperation string) {
		selectors := make([]string, len(names))
		for i, name := range names {
			selectors[i] = fmt.Sprintf("target.secret.name='%s'", name)
		}
		for _, operation := range originalStartupPublicationOperations() {
			if operation.Operation == "GetSecretBundle" {
				operation.Operation = bundleOperation
			}
			extra, verb := "", "use"
			switch operation.Scope {
			case "regional-control-list":
				verb = "inspect"
			case "material-names-vault":
				verb = "read"
				if operation.Permission == "SECRET_CREATE" {
					verb = "manage"
				}
				extra = fmt.Sprintf("target.vault.id='%s', any {%s}", target.VaultOCID, strings.Join(selectors, ", "))
			case "material-vault":
				extra = fmt.Sprintf("target.vault.id='%s'", target.VaultOCID)
			case "material-key":
				extra = fmt.Sprintf("target.key.id='%s'", target.KMSKeyOCID)
			}
			add(actor, target.CompartmentOCID, verb, operation.ResourceType, operation.Operation, operation.Permission, extra)
		}
	}
	for _, region := range startup.Regions {
		principal := actor
		homeIssuer := region.Producer.Cell == "GRU" && scope.Recipe.Cell != "GRU"
		if region.Producer.Cell == scope.Recipe.Cell || homeIssuer {
			principal = peer
		} else if scope.Recipe.Cell != "GRU" {
			continue
		}
		for _, op := range [][2]string{{"GetVcn", "VCN_READ"}, {"GetSubnet", "SUBNET_READ"}, {"GetNetworkSecurityGroup", "NETWORK_SECURITY_GROUP_READ"}} {
			read(principal, region.NetworkCompartmentID, op[0], op[1], "")
		}
		read(principal, region.Target.CompartmentOCID, "GetVault", "VAULT_READ", fmt.Sprintf("target.vault.id='%s'", region.Target.VaultOCID))
		read(principal, region.Target.CompartmentOCID, "GetKey", "KEY_READ", fmt.Sprintf("target.key.id='%s'", region.Target.KMSKeyOCID))
		var names []string
		if region.Producer.Cell == scope.Recipe.Cell {
			names = slices.Clone(region.SecretNames)
		}
		if scope.Recipe.Cell == "GRU" {
			names = append(names, region.LinkSecretNames[:]...)
		}
		if !homeIssuer {
			publish(region.Target, names, "GetSecretBundle")
		}
		if region.Producer.Cell == scope.Recipe.Cell && scope.Recipe.Purpose == "original-material-publication-iam/v4" {
			publish(region.Target, []string{scope.Recipe.RuntimeJoinSecretName}, "GetSecretBundleByName")
		}
		if region.Producer.Cell != scope.Recipe.Cell {
			read(principal, region.ImageCompartmentID, "GetImage", "INSTANCE_IMAGE_INSPECT", fmt.Sprintf("target.image.id='%s'", region.Producer.ImageOCID))
			for _, op := range [][2]string{{"GetInstance", "INSTANCE_READ"}, {"ListVnicAttachments", "INSTANCE_INSPECT"}, {"ListVnicAttachments", "VNIC_ATTACHMENT_READ"}, {"GetBootVolume", "VOLUME_INSPECT"}, {"ListBootVolumeAttachments", ""}} {
				read(principal, region.Target.CompartmentOCID, op[0], op[1], "")
			}
			read(principal, region.NetworkCompartmentID, "GetVnic", "VNIC_READ", "")
			continue
		}
		for _, resource := range []string{"instance-family", "volume-family"} {
			add(actor, region.Target.CompartmentOCID, "manage", resource, "LaunchInstance", "", "")
		}
		add(actor, region.NetworkCompartmentID, "use", "virtual-network-family", "LaunchInstance", "", "")
		add(actor, region.ImageCompartmentID, "read", "instance-images", "LaunchInstance", "", fmt.Sprintf("target.image.id='%s'", region.Producer.ImageOCID))
		read(peer, region.ImageCompartmentID, "GetImage", "INSTANCE_IMAGE_INSPECT", fmt.Sprintf("target.image.id='%s'", region.Producer.ImageOCID))
		for _, op := range [][2]string{{"GetInstance", "INSTANCE_READ"}, {"ListVnicAttachments", "INSTANCE_INSPECT"}, {"ListVnicAttachments", "VNIC_ATTACHMENT_READ"}, {"GetBootVolume", "VOLUME_INSPECT"}, {"ListBootVolumeAttachments", ""}} {
			read(peer, region.Target.CompartmentOCID, op[0], op[1], "")
		}
		read(peer, region.NetworkCompartmentID, "GetVnic", "VNIC_READ", "")
		// Every admitted compartment instance can read all non-source bundles, including founder names.
		add(peer, region.Target.CompartmentOCID, "read", "secret-bundles", "GetSecretBundle", "SECRET_BUNDLE_READ", "target.secret.name != /ts-bootstrap-source-*/")
		if scope.Recipe.Purpose == "original-material-publication-iam/v4" {
			add(peer, region.Target.CompartmentOCID, "read", "secret-bundles", "GetSecretBundleByName", "SECRET_BUNDLE_READ", fmt.Sprintf("target.vault.id='%s', target.secret.name='%s'", region.Target.VaultOCID, scope.Recipe.RuntimeJoinSecretName))
		}
		add(peer, region.Target.CompartmentOCID, "inspect", "secrets", "ListSecrets", "SECRET_INSPECT", "")
		add(peer, region.Target.CompartmentOCID, "read", "secrets", "GetSecret", "SECRET_READ", "target.secret.name != /ts-bootstrap-source-*/")
	}
	type objectKey struct{ principal, bucket, operation, permission string }
	objects := map[objectKey][]string{}
	var objectOrder []objectKey
	object := func(principal, bucket, name, operation, permission string) {
		key := objectKey{principal, bucket, operation, permission}
		if objects[key] == nil {
			objectOrder = append(objectOrder, key)
		}
		selector := "target.object.name=" + name
		if !slices.Contains(objects[key], selector) {
			objects[key] = append(objects[key], selector)
		}
	}
	var escrowNames []string
	for _, region := range startup.Regions {
		if region.Producer.Cell == "GRU" && scope.Recipe.Cell != "GRU" {
			object(peer, startup.Producer.Home.HeadBucket, "'"+region.Producer.SourceObject+"'", "GetObject", "OBJECT_READ")
		}
		if region.Producer.Cell == scope.Recipe.Cell {
			object(peer, startup.Producer.Home.HeadBucket, "'"+region.Producer.SourceObject+"'", "GetObject", "OBJECT_READ")
			object(peer, startup.Producer.Home.HeadBucket, "'"+region.LinkObject+"'", "GetObject", "OBJECT_READ")
		}
		if scope.Recipe.Cell == "GRU" {
			object(actor, startup.Producer.Home.HeadBucket, "'"+region.Producer.SourceObject+"'", "GetObject", "OBJECT_READ")
			object(actor, startup.Producer.Home.HeadBucket, "'"+region.LinkObject+"'", "GetObject", "OBJECT_READ")
			for _, permission := range []string{"OBJECT_CREATE", "OBJECT_OVERWRITE"} {
				object(actor, startup.Producer.Home.HeadBucket, "'"+region.LinkObject+"'", "PutObject", permission)
			}
			escrowNames = append(escrowNames, region.LinkEscrowSecretName)
		}
	}
	if scope.Recipe.Cell == "GRU" {
		publish(startup.Producer.Escrow, escrowNames, "GetSecretBundle")
	}
	for _, key := range []string{"orchestrator/foundation/v1/root-chain.json", strings.TrimSuffix(startup.Producer.Home.Prefix, "/") + "/" + "foundation-scope-v1.json", "orchestrator/regions/v1/" + "GRU.json", "orchestrator/foundation/v1/anchor.json"} {
		object(peer, startup.Producer.Home.HeadBucket, "'"+key+"'", "GetObject", "OBJECT_READ")
		if scope.Recipe.Cell == "GRU" {
			object(actor, startup.Producer.Home.HeadBucket, "'"+key+"'", "GetObject", "OBJECT_READ")
		}
	}
	for _, permission := range []string{"OBJECT_CREATE", "OBJECT_OVERWRITE"} {
		object(actor, startup.Producer.Home.HeadBucket, "'"+startup.Producer.SourceObject+"'", "PutObject", permission)
	}
	for _, slot := range []string{"controller-a", "controller-b", "controller-c"} {
		identity := sha256.Sum256([]byte(scope.Recipe.Cell + "\x00controller\x00" + slot))
		root := "bootstrap/v1/" + startup.Producer.DeploymentID + "/" + hex.EncodeToString(identity[:])
		if startup.Producer.Home.Prefix != "" {
			root = startup.Producer.Home.Prefix + "/" + root
		}
		// The IAM terminal wildcard is broader than the signed closed-kind/attempt parser.
		for _, permission := range []string{"OBJECT_READ", "OBJECT_CREATE"} {
			operation := "PutObject"
			if permission == "OBJECT_READ" {
				operation = "GetObject"
			}
			principal := peer
			if permission == "OBJECT_CREATE" {
				principal = actor
			}
			object(principal, startup.Producer.Home.LedgerBucket, "/"+root+"/*/", operation, permission)
			object(peer, startup.Producer.Home.HeadBucket, "'"+root+"/accepted-install.json'", operation, permission)
		}
		for _, key := range []string{"'" + root + "/head.json'", "/" + root + "/attempt-*/"} {
			object(peer, startup.Producer.Home.HeadBucket, key, "GetObject", "OBJECT_READ")
			for _, permission := range []string{"OBJECT_CREATE", "OBJECT_OVERWRITE"} {
				object(actor, startup.Producer.Home.HeadBucket, key, "PutObject", permission)
			}
		}
	}
	for _, key := range objectOrder {
		extra := fmt.Sprintf("target.bucket.name='%s', any {%s}", key.bucket, strings.Join(objects[key], ", "))
		add(key.principal, startup.HomeControlCompartmentID, "manage", "objects", key.operation, key.permission, extra)
	}
	statements := make([]string, 0, len(order))
	for _, key := range order {
		location := "compartment id " + key.compartment
		if key.compartment == scope.Recipe.TenancyID {
			location = "tenancy"
		}
		conditions := "any {" + strings.Join(groups[key], ", ") + "}"
		if key.principal == actor {
			conditions = fmt.Sprintf("request.principal.type='instance', request.principal.id='%s', %s", scope.ActorID, conditions)
		}
		statements = append(statements, fmt.Sprintf("Allow %s to %s %s in %s where all {%s}", key.principal, key.verb, key.resource, location, conditions))
	}
	return statements, nil
}
