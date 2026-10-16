package app

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/placement"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// A TerraBase deployment state directory. Every file is created once and
// never rewritten, so a rerun resumes from the first missing step and a
// changed plan is detected instead of silently producing a second scope.
const (
	deployIdentityFile        = "identity.json"
	deployArtifactFile        = "artifact.json"
	deploySpecFile            = "spec.json"
	deployMaterialFile        = "material-reply.json"
	deployCustomerDirectory   = "customer"
	deployCredentialsFile     = "customer/credentials.json"
	deployCAFile              = "customer/https-ca.pem"
	deployClientFile          = "customer/client.json"
	deployIntentFile          = "placement-intent.json"
	deployPlacementFile       = "placement-receipt.json"
	terrabaseDeployPlanSchema = 1
	maxDeployStateFileBytes   = 256 << 10
	maxGrantValidityHours     = 30 * 24
	// The client profile lists collection properties by name, as TerraBase's
	// named JSON document writes address them.
	terrabaseClientProfileVersion = 2
)

type terrabaseDeployMember struct {
	PrivateIP   string `json:"private_ip"`
	FaultDomain string `json:"fault_domain"`
}

type terrabaseDeployRecipient struct {
	SignerKey          string `json:"signer_key"`
	SignerPublicKey    string `json:"signer_public_key"`
	RecipientKey       string `json:"recipient_key"`
	GrantValidityHours uint32 `json:"grant_validity_hours"`
}

// terrabaseDeployPlan is the whole operator input for a first TerraBase
// deployment into a running regional cell. Members are listed in placement
// seat order: the first uses the controller's first configured fault domain.
type terrabaseDeployPlan struct {
	Version             int                          `json:"version"`
	PlacementDatabaseID string                       `json:"placement_database_id"`
	PartitionID         string                       `json:"partition_id"`
	Role                string                       `json:"role"`
	Environment         string                       `json:"environment"`
	Release             terrabaseReleaseFiles        `json:"release"`
	HostProfile         placement.ManagedHostProfile `json:"host_profile"`
	ManagedRuntimeRoot  string                       `json:"managed_runtime_root"`
	Members             [2]terrabaseDeployMember     `json:"members"`
	ReplicationPort     uint16                       `json:"replication_port"`
	ClientPort          uint16                       `json:"client_port"`
	LiveS3              managedmaterial.LiveS3Target `json:"live_s3"`
	Collections         int                          `json:"collections"`
	Recipient           terrabaseDeployRecipient     `json:"recipient"`
}

// terrabaseClientProfile is the customer-facing summary written next to the
// opened credentials: scope, collections and member HTTPS endpoints.
type terrabaseClientProfile struct {
	Version     int                         `json:"version"`
	TenantID    string                      `json:"tenant_id"`
	DatabaseID  string                      `json:"database_id"`
	ShardID     uint64                      `json:"shard_id"`
	Collections []terrabaseClientCollection `json:"collections"`
	Members     []terrabaseClientMember     `json:"members"`
}

// terrabaseClientCollection names one collection, the optional UTF-8 string
// properties its enforced schema declares, and the catalog binding that
// TerraBase reports on every live document version written under it.
type terrabaseClientCollection struct {
	CollectionID     string   `json:"collection_id"`
	SchemaGeneration uint64   `json:"schema_generation"`
	SchemaDigest     string   `json:"schema_digest"`
	UTF8Fields       []string `json:"utf8_fields"`
}

type terrabaseClientMember struct {
	SeatID     string `json:"seat_id"`
	MemberID   string `json:"member_id"`
	URL        string `json:"url"`
	ServerName string `json:"server_name"`
}

type terrabaseDeployStep struct {
	Step   string `json:"step"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

func loadTerraBaseDeployPlan(path string, cell string) (terrabaseDeployPlan, oci.Region, error) {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return terrabaseDeployPlan{}, "", fmt.Errorf("read TerraBase deployment plan: %w", err)
	}
	var plan terrabaseDeployPlan
	if err := json.Unmarshal(data, &plan, json.RejectUnknownMembers(true)); err != nil {
		return terrabaseDeployPlan{}, "", fmt.Errorf("decode TerraBase deployment plan: %w", err)
	}
	region := oci.Region(strings.ToUpper(cell))
	if plan.HostProfile.Region == "" {
		plan.HostProfile.Region = region
	}
	if plan.Version != terrabaseDeployPlanSchema || plan.Role == "" || plan.Environment == "" ||
		plan.HostProfile.Region != region || plan.Collections < 1 || plan.Collections > 16 ||
		plan.Recipient.GrantValidityHours == 0 || plan.Recipient.GrantValidityHours > maxGrantValidityHours {
		return terrabaseDeployPlan{}, "", errors.New("TerraBase deployment plan version, role, environment, region, collections or grant validity is invalid")
	}
	if err := plan.HostProfile.Validate(); err != nil {
		return terrabaseDeployPlan{}, "", err
	}
	// Placement names member i gru-1-db-i by seat order and NetBird names it by
	// address; GRU's fixed cell slots keep the two the same host.
	if region == oci.RegionGRU {
		slots := manager.GRU().PeerNames()
		for index, member := range plan.Members {
			if want, err := naming.RegionCell(string(region)).Server(naming.Member, index+1); err != nil || slots[member.PrivateIP] != want {
				return terrabaseDeployPlan{}, "", fmt.Errorf("TerraBase deployment member %d must use the %s cell address", index+1, want)
			}
		}
	}
	// Validate every plan-owned pin with throwaway identities before any effect.
	candidate, err := managedmaterial.NewDeploymentIdentity(plan.base(region), plan.Collections)
	if err != nil {
		return terrabaseDeployPlan{}, "", err
	}
	if err := candidate.Validate(); err != nil {
		return terrabaseDeployPlan{}, "", fmt.Errorf("TerraBase deployment plan: %w", err)
	}
	return plan, region, nil
}

// base maps the plan onto a deployment without generated identities.
func (plan terrabaseDeployPlan) base(region oci.Region) managedmaterial.InitialDeployment {
	seats, _ := placement.RegionSeatIDs(region)
	deployment := managedmaterial.InitialDeployment{Region: region,
		PlacementDatabaseID: plan.PlacementDatabaseID, PartitionID: plan.PartitionID, LiveS3: plan.LiveS3,
		ReplicationPort: plan.ReplicationPort, ClientPort: plan.ClientPort, ManagedRuntimeRoot: plan.ManagedRuntimeRoot}
	for index, member := range plan.Members {
		deployment.Members[index] = managedmaterial.DeploymentMember{SeatID: seats[index],
			ServerName:    strings.ToLower(seats[index]+"."+plan.PartitionID+"."+plan.PlacementDatabaseID) + ".terrabase.internal",
			FailureDomain: member.FaultDomain, PrivateIP: member.PrivateIP}
	}
	return deployment
}

// operatorTerraBaseDeploy pushes the release, prepares and opens generation
// one material, renders the schema-5 placement from the signed receipt and
// applies it. Each completed step is retained in the state directory.
func operatorTerraBaseDeploy(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	planPath, statePath string, output io.Writer,
) error {
	plan, region, err := loadTerraBaseDeployPlan(planPath, cfg.NATS.Cell)
	if err != nil {
		return err
	}
	release, err := loadTerraBaseRelease(plan.Release)
	if err != nil {
		return err
	}
	state, err := openDeployState(statePath)
	if err != nil {
		return err
	}
	report := func(step, status, detail string) error {
		return printJSON(output, terrabaseDeployStep{Step: step, Status: status, Detail: detail})
	}
	deployment, created, err := state.deployment(plan, region)
	if err != nil {
		return err
	}
	if err := report("identity", reusedOr(created, "generated"), deployment.Scope.ClusterID); err != nil {
		return err
	}
	record, err := pushArtifact(ctx, cfg, runtime, release.Binary, delivery.ArtifactClaimRequest{
		Source: release.Source, Cell: cfg.NATS.Cell, Role: plan.Role, Environment: plan.Environment})
	if err != nil {
		return fmt.Errorf("push TerraBase artifact: %w", err)
	}
	if record.Digest != release.Digest || record.Source != release.Source {
		return errors.New("controller admitted different TerraBase artifact bytes or source")
	}
	if _, err := state.ensureJSON(deployArtifactFile, record); err != nil {
		return err
	}
	if err := retainReleaseCompatibility(state, release); err != nil {
		return err
	}
	if err := report("artifact", "admitted", record.Digest); err != nil {
		return err
	}
	recipient, err := managedmaterial.ReadRecipientKey(plan.Recipient.RecipientKey)
	if err != nil {
		return err
	}
	signerPublic, err := managedmaterial.ReadRecipientSignerPublic(plan.Recipient.SignerPublicKey)
	if err != nil {
		return err
	}
	spec, created, err := state.spec(deployment, plan.Recipient, recipient.PublicKey().Bytes(), signerPublic,
		func(draft managedmaterial.InitialSpec) (managedmaterial.InitialSpec, error) {
			signer, err := managedmaterial.ReadRecipientSigner(plan.Recipient.SignerKey)
			if err != nil {
				return managedmaterial.InitialSpec{}, err
			}
			defer clear(signer)
			if !signer.Public().(ed25519.PublicKey).Equal(signerPublic) {
				return managedmaterial.InitialSpec{}, errors.New("recipient signer differs from its pinned public key")
			}
			now := time.Now().UTC()
			return managedmaterial.SignRecipientGrant(draft, recipient, signer,
				now.Add(time.Duration(plan.Recipient.GrantValidityHours)*time.Hour), now)
		})
	if err != nil {
		return err
	}
	if err := report("spec", reusedOr(created, "signed"), spec.Recipient.ExpiresAt.Format(time.RFC3339)); err != nil {
		return err
	}
	controllerKey, err := decodePublicKey(cfg.Operator.ControllerPublicKey)
	if err != nil {
		return fmt.Errorf("operator controller key pin: %w", err)
	}
	var reply materialPrepareReply
	exists, err := state.readJSON(deployMaterialFile, &reply)
	if err != nil {
		return err
	}
	if exists {
		if err := verifyMaterialPrepareReply(reply, controllerKey, cfg.NATS.Cell, spec); err != nil {
			return fmt.Errorf("retained material reply: %w", err)
		}
	} else {
		reply, err = requestMaterialPreparation(ctx, cfg, runtime, spec)
		if err != nil {
			return err
		}
		if _, err := state.ensureJSON(deployMaterialFile, reply); err != nil {
			return err
		}
	}
	if err := report("material", reusedOr(!exists, "prepared"), reply.Receipt.Object.Name); err != nil {
		return err
	}
	opened, err := state.customer(spec, reply, recipient, deployment)
	if err != nil {
		return err
	}
	if err := report("customer", reusedOr(opened, "opened"), filepath.Join(state.directory, deployCustomerDirectory)); err != nil {
		return err
	}
	intent, err := managedmaterial.RenderInitialPlacement(reply.Receipt, deployment,
		managedmaterial.RuntimeArtifact{Digest: record.Digest, SourceDigest: record.Source.TreeDigest}, plan.HostProfile)
	if err != nil {
		return err
	}
	if _, err := state.ensureJSON(deployIntentFile, intent); err != nil {
		return err
	}
	response, err := applyPlacement(ctx, cfg, runtime, intent)
	if err != nil {
		return err
	}
	if _, err := state.readOrCreateJSON(deployPlacementFile, response); err != nil {
		return err
	}
	if err := report("placement", "admitted", fmt.Sprintf("sequence %d", response.Sequence)); err != nil {
		return err
	}
	return report("deploy", "applied", "watch with: operator terrabase-status --state "+state.directory+" --wait 30m")
}

func reusedOr(created bool, action string) string {
	if created {
		return action
	}
	return "reused"
}

type deployState struct{ directory string }

// openDeployState creates or reopens an owner-only state directory.
func openDeployState(path string) (deployState, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return deployState{}, errors.New("--state must be a clean absolute directory")
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return deployState{}, err
	}
	for _, directory := range []string{path, filepath.Join(path, deployCustomerDirectory),
		filepath.Join(path, deployReleaseDirectory), filepath.Join(path, deployKnownBadDirectory)} {
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return deployState{}, err
		}
		info, err := os.Lstat(directory)
		if err != nil {
			return deployState{}, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.IsDir() || info.Mode().Perm() != 0o700 || !ok || stat.Uid != uint32(os.Getuid()) {
			return deployState{}, fmt.Errorf("%s must be an owner-only directory of this user", directory)
		}
	}
	return deployState{directory: path}, nil
}

func (state deployState) readJSON(name string, value any) (bool, error) {
	data, err := state.readFile(name)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := json.Unmarshal(data, value, json.RejectUnknownMembers(true)); err != nil {
		return false, fmt.Errorf("decode retained %s: %w", name, err)
	}
	return true, nil
}

func (state deployState) readFile(name string) ([]byte, error) {
	fd, err := syscall.Open(filepath.Join(state.directory, name), syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maxDeployStateFileBytes {
		return nil, fmt.Errorf("retained %s must be a bounded owner-only file", name)
	}
	return io.ReadAll(io.LimitReader(file, maxDeployStateFileBytes+1))
}

// ensureJSON creates a canonical state file or requires the retained file to
// hold exactly the same bytes. It reports whether the file was created.
func (state deployState) ensureJSON(name string, value any) (bool, error) {
	wire, err := protocol.EncodeJSON(value)
	if err != nil {
		return false, err
	}
	existing, err := state.readFile(name)
	if err == nil {
		if !bytes.Equal(existing, wire) {
			return false, fmt.Errorf("retained %s differs from this plan; use a new --state and partition to deploy a different plan", name)
		}
		return false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return true, state.createFile(name, wire)
}

// readOrCreateJSON keeps the first retained value of an observation, such as
// an admission receipt whose sequence can differ on an idempotent replay.
func (state deployState) readOrCreateJSON(name string, value any) (bool, error) {
	if _, err := state.readFile(name); err == nil {
		return false, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	wire, err := protocol.EncodeJSON(value)
	if err != nil {
		return false, err
	}
	return true, state.createFile(name, wire)
}

// createFile publishes complete bytes through a synced temporary file and a
// create-only link, so an interrupted run never leaves a partial state file.
func (state deployState) createFile(name string, contents []byte) error {
	target := filepath.Join(state.directory, name)
	file, err := os.CreateTemp(filepath.Dir(target), ".ts-deploy-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(temporary, target); err != nil {
		return fmt.Errorf("publish %s without overwrite: %w", name, err)
	}
	directory, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

// deployment loads the retained identities or generates them once. A plan
// edit that would change a signed pin is rejected.
func (state deployState) deployment(plan terrabaseDeployPlan, region oci.Region) (managedmaterial.InitialDeployment, bool, error) {
	base := plan.base(region)
	var retained managedmaterial.InitialDeployment
	exists, err := state.readJSON(deployIdentityFile, &retained)
	if err != nil {
		return managedmaterial.InitialDeployment{}, false, err
	}
	if !exists {
		generated, err := managedmaterial.NewDeploymentIdentity(base, plan.Collections)
		if err != nil {
			return managedmaterial.InitialDeployment{}, false, err
		}
		if err := generated.Validate(); err != nil {
			return managedmaterial.InitialDeployment{}, false, err
		}
		_, err = state.ensureJSON(deployIdentityFile, generated)
		return generated, true, err
	}
	expected := retained
	expected.Region, expected.PlacementDatabaseID, expected.PartitionID = base.Region, base.PlacementDatabaseID, base.PartitionID
	expected.LiveS3, expected.ReplicationPort, expected.ClientPort = base.LiveS3, base.ReplicationPort, base.ClientPort
	expected.ManagedRuntimeRoot = base.ManagedRuntimeRoot
	for index := range expected.Members {
		member := &expected.Members[index]
		member.SeatID, member.ServerName = base.Members[index].SeatID, base.Members[index].ServerName
		member.FailureDomain, member.PrivateIP = base.Members[index].FailureDomain, base.Members[index].PrivateIP
	}
	want, err := protocol.EncodeJSON(expected)
	if err != nil {
		return managedmaterial.InitialDeployment{}, false, err
	}
	got, err := protocol.EncodeJSON(retained)
	if err != nil || !bytes.Equal(want, got) || len(retained.CollectionIDs) != plan.Collections {
		return managedmaterial.InitialDeployment{}, false,
			errors.New("deployment plan changed after identities were generated; use a new --state and partition")
	}
	return retained, false, retained.Validate()
}

// spec loads the retained signed spec or signs the deployment draft once.
func (state deployState) spec(deployment managedmaterial.InitialDeployment, recipient terrabaseDeployRecipient,
	recipientPublic []byte, signerPublic ed25519.PublicKey,
	sign func(managedmaterial.InitialSpec) (managedmaterial.InitialSpec, error),
) (managedmaterial.InitialSpec, bool, error) {
	var spec managedmaterial.InitialSpec
	exists, err := state.readJSON(deploySpecFile, &spec)
	if err != nil {
		return managedmaterial.InitialSpec{}, false, err
	}
	if !exists {
		draft, err := deployment.DraftSpec()
		if err != nil {
			return managedmaterial.InitialSpec{}, false, err
		}
		spec, err = sign(draft)
		if err != nil {
			return managedmaterial.InitialSpec{}, false, err
		}
		_, err = state.ensureJSON(deploySpecFile, spec)
		return spec, true, err
	}
	if err := deployment.MatchesSpec(spec); err != nil {
		return managedmaterial.InitialSpec{}, false, err
	}
	if !bytes.Equal(spec.Recipient.PublicKey, recipientPublic) {
		return managedmaterial.InitialSpec{}, false, errors.New("retained material spec names a different recipient key")
	}
	return spec, false, managedmaterial.VerifyRecipientGrant(spec, signerPublic)
}

// customer opens the authenticated customer envelope once and writes the
// owner-only token, HTTPS CA and client profile.
func (state deployState) customer(spec managedmaterial.InitialSpec, reply materialPrepareReply,
	recipient *ecdh.PrivateKey, deployment managedmaterial.InitialDeployment,
) (bool, error) {
	material, err := managedmaterial.OpenCustomerEnvelope(spec, reply.Customer, recipient)
	if err != nil {
		return false, err
	}
	created, err := state.readOrCreateJSON(deployCredentialsFile, material)
	if err != nil {
		return false, err
	}
	if _, err := state.readFile(deployCAFile); errors.Is(err, os.ErrNotExist) {
		if err := state.createFile(deployCAFile, []byte(material.HTTPSCAPEM)); err != nil {
			return false, err
		}
	} else if err != nil {
		return false, err
	}
	profile := terrabaseClientProfile{Version: terrabaseClientProfileVersion, TenantID: spec.Scope.TenantID,
		DatabaseID: spec.Scope.DatabaseID, ShardID: spec.Scope.ShardID}
	fields := make([]string, 0, len(managedmaterial.DeploymentDocumentFields))
	for _, field := range managedmaterial.DeploymentDocumentFields {
		fields = append(fields, field.Name)
	}
	for _, catalog := range spec.Catalogs {
		built, err := managedmaterial.InitialCatalog(catalog.CollectionID, managedmaterial.DeploymentDocumentFields)
		if err != nil || !bytes.Equal(built.Bytes, catalog.CanonicalCatalog) {
			return false, errors.New("retained catalog differs from the deployment document schema")
		}
		profile.Collections = append(profile.Collections, terrabaseClientCollection{CollectionID: catalog.CollectionID,
			SchemaGeneration: built.SchemaGeneration, SchemaDigest: built.SchemaDigest, UTF8Fields: fields})
	}
	for _, member := range deployment.Members {
		profile.Members = append(profile.Members, terrabaseClientMember{SeatID: member.SeatID, MemberID: member.MemberID,
			URL:        fmt.Sprintf("https://%s:%d", member.PrivateIP, deployment.ClientPort),
			ServerName: member.ServerName})
	}
	if _, err := state.ensureJSON(deployClientFile, profile); err != nil {
		return false, err
	}
	return created, nil
}
