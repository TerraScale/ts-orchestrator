//go:build sandboxvm

package vmqualruntime

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/vmcandidateseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"
)

// LocalQualificationMaterialInput carries exact caller-owned runtime intent.
// ControlPayload uses the control declaration payload schema; member key
// references and pins are generated here. Store and candidate reader references
// must already name provisioned local material. RunDeclaration is preserved,
// never replaced with a permissive placeholder production configuration.
type LocalQualificationMaterialInput struct {
	Network        vmnet.NetworkPlan            `json:"network"`
	NetworkConfig  vmnet.Config                 `json:"networkConfig"`
	Architecture   vmimage.Architecture         `json:"architecture"`
	Artifacts      []vmimage.GuestArtifact      `json:"artifacts"`
	ControlPayload jsontext.Value               `json:"controlPayload"`
	RunDeclaration vmcontrolseed.RunDeclaration `json:"runDeclaration"`
}

type LocalQualificationMaterialIntent struct {
	NetworkConfig  vmnet.Config                           `json:"networkConfig"`
	Architecture   vmimage.Architecture                   `json:"architecture"`
	Artifacts      []vmimage.GuestArtifact                `json:"artifacts"`
	RunDeclaration vmcontrolseed.RunDeclaration           `json:"runDeclaration"`
	Control        LocalQualificationControlIntentRequest `json:"control"`
}

// GenerateLocalQualificationMaterial creates a new private local admission
// directory and signs the loader's exact payload types. It never starts guests
// or contacts a provider. Output must be an empty, private directory: retries
// cannot silently replace an already admitted random identity.
func GenerateLocalQualificationMaterial(root string, input LocalQualificationMaterialInput) error {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || strings.ContainsAny(root, "\x00\r\n") || input.Network.Validate() != nil {
		return errors.New("vmqual material: clean output and canonical network required")
	}
	if input.NetworkConfig.RunID != input.Network.RunID || input.NetworkConfig.TAPUID == 0 || input.NetworkConfig.TAPGID == 0 || input.NetworkConfig.CoordinationRoot != "" {
		return errors.New("vmqual material: explicit network config does not retain production ownership")
	}
	planned, err := vmnet.Plan(input.NetworkConfig)
	if err != nil || !reflect.DeepEqual(planned, input.Network) {
		return errors.New("vmqual material: network config differs from canonical plan")
	}
	var payload qualificationControlPayload
	if err := json.Unmarshal(input.ControlPayload, &payload, json.RejectUnknownMembers(true)); err != nil {
		return fmt.Errorf("vmqual material intent: %w", err)
	}
	if len(payload.Members) != 6 || len(input.RunDeclaration.Hosts) != 6 || payload.CandidatePlan == nil {
		return errors.New("vmqual material: six members, six run admissions and staged candidate intent required")
	}
	runHosts := map[string]uint64{}
	for _, host := range input.RunDeclaration.Hosts {
		if host.Generation == 0 || runHosts[host.HostID] != 0 {
			return errors.New("vmqual material: duplicate run host or missing generation")
		}
		runHosts[host.HostID] = host.Generation
	}
	for _, member := range payload.Members {
		if member.Generation <= 0 || uint64(member.Generation) != runHosts[member.Member.HostID] {
			return errors.New("vmqual material: run and control host generations differ")
		}
	}
	for name := range payload.Stores {
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
			return errors.New("vmqual material: store name must be a single path component")
		}
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("vmqual material: output must be a private directory")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return errors.New("vmqual material: output directory must be empty")
	}
	write := func(name string, raw []byte, mode os.FileMode) (qualificationControlFile, error) {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return qualificationControlFile{}, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return qualificationControlFile{}, err
		}
		_, writeErr := f.Write(raw)
		if err := errors.Join(writeErr, f.Close()); err != nil {
			return qualificationControlFile{}, err
		}
		sum := sha256.Sum256(raw)
		return qualificationControlFile{Source: path, SHA256: hex.EncodeToString(sum[:])}, nil
	}
	guests := map[string]vmcontrolseed.Guest{}
	regions := map[string]string{}
	for _, region := range input.Network.Regions {
		for _, guest := range region.Guests {
			regions[guest.ID] = string(region.Code)
			guests[guest.ID] = vmcontrolseed.Guest{ID: guest.ID, Address: guest.Address}
		}
	}
	seen := map[string]bool{}
	var gru []vmcontrolseed.Guest
	for i := range payload.Members {
		entry := &payload.Members[i]
		guest, ok := guests[entry.Member.HostID]
		if !ok || seen[guest.ID] {
			return errors.New("vmqual material: member differs from network")
		}
		seen[guest.ID] = true
		identity, err := newQualificationMembershipIdentity()
		if err != nil {
			return err
		}
		ref, err := write(filepath.Join("membership", guest.ID+".private.pem"), identity.PrivatePEM, 0600)
		clear(identity.PrivatePEM)
		if err != nil {
			return err
		}
		entry.MembershipKey, entry.Member.IdentityPublicKey = ref, identity.PublicKey
		guest.MembershipPublicKey = identity.PublicKey
		if regions[guest.ID] == "GRU" {
			gru = append(gru, guest)
		}
	}
	stateRoot := filepath.Join(root, "state")
	retainedRunID, err := RetainQualificationRunIdentity(stateRoot, input.NetworkConfig)
	if err != nil || retainedRunID != input.Network.RunID {
		return errors.New("vmqual material: retained network identity differs from plan")
	}
	state := filepath.Join(stateRoot, "qualification-admission-"+input.Network.RunID)
	seeds, err := vmcontrolseed.LoadOrCreateGRU(state, input.Network.RunID, gru, func() (map[string]vmcontrolseed.Material, error) {
		return vmcontrolseed.GenerateGRU(input.Network.RunID, gru)
	})
	if err != nil {
		return err
	}
	defer func() {
		for _, seed := range seeds {
			seed.Clear()
		}
	}()
	// Rebind GRU reader references to the exact broker material reopened by the
	// runtime. Independent generated credentials would pass the file loader but
	// fail authentication against the initial guest broker.
	for name, store := range payload.Stores {
		for _, seed := range seeds {
			if !seed.Selected {
				continue
			}
			config, err := initialgrant.ParseConfig([]byte(seed.Settings))
			if err != nil {
				return err
			}
			if store.Reader.Endpoint != config.Broker.Endpoint {
				continue
			}
			if store.Reader.ServerName != "" && store.Reader.ServerName != config.Broker.ServerName || store.Reader.Account != "" && store.Reader.Account != config.Regional.Account {
				return errors.New("vmqual material: initial source store scope differs from GRU broker")
			}
			connection := config.Regional.Runtime
			reader := nodeauthority.ReaderConfig{Endpoint: config.Broker.Endpoint, ServerName: config.Broker.ServerName, Account: config.Regional.Account, NKeySeedFile: connection.NKeySeedFile, PublicNKey: connection.PublicNKey, CAFile: connection.TLS.CAFile, CASHA256: connection.TLS.CASHA256, CertificateFile: connection.TLS.CertificateFile, CertificateSHA256: connection.TLS.CertificateSHA256, KeyFile: connection.TLS.KeyFile}
			store.Reader, store.Files = reader, map[string]qualificationControlFile{}
			for _, path := range []string{reader.NKeySeedFile, reader.CAFile, reader.CertificateFile, reader.KeyFile} {
				ref, err := write(filepath.Join("stores", name, filepath.Base(path)), seed.Files[path], 0600)
				if err != nil {
					return err
				}
				store.Files[path] = ref
			}
			payload.Stores[name] = store
			for i := range payload.Members {
				entry := &payload.Members[i]
				if entry.Member.Store != name {
					continue
				}
				material := seed
				if own, ok := seeds[entry.Member.HostID]; ok {
					material = own
				}
				reader, err := material.AuthorityReader()
				if err != nil {
					return err
				}
				declared := qualificationControlStoreDeclaration{Reader: reader, Files: map[string]qualificationControlFile{}}
				for _, path := range []string{reader.NKeySeedFile, reader.CAFile, reader.CertificateFile, reader.KeyFile} {
					ref, err := write(filepath.Join("readers", entry.Member.HostID, filepath.Base(path)), material.Files[path], 0600)
					if err != nil {
						return err
					}
					declared.Files[path] = ref
				}
				entry.AuthorityReader = &declared
				for j := range payload.CandidatePlan.Candidates {
					candidate := &payload.CandidatePlan.Candidates[j]
					if candidate.Config.NodeID != entry.Member.HostID {
						continue
					}
					candidate.SyncGeneration = &vmcandidateseed.Declaration{Reader: reader, ReaderNKeyFile: declared.Files[reader.NKeySeedFile].Source, ReaderCAFile: declared.Files[reader.CAFile].Source, ReaderCertificateFile: declared.Files[reader.CertificateFile].Source, ReaderPrivateKeyFile: declared.Files[reader.KeyFile].Source}
				}
			}
		}
	}
	issuer, err := vmqualbootstrap.NewPersistentIssuer(state, input.Network.RunID)
	if err != nil {
		return err
	}
	if err := issuer.Close(); err != nil {
		return err
	}
	// The existing constructor above validates and owns this durable document.
	// Read its signing capability only within the protected generator process.
	raw, err := bootstrapcredentials.ReadFile(filepath.Join(state, "initial-issuer.json"), true, 64<<10)
	if err != nil {
		return err
	}
	defer clear(raw)
	var owner struct {
		PrivatePEM []byte    `json:"privatePem"`
		IssuedAt   time.Time `json:"issuedAt"`
	}
	if err := json.Unmarshal(raw, &owner); err != nil {
		return err
	}
	defer clear(owner.PrivatePEM)
	block, _ := pem.Decode(owner.PrivatePEM)
	if block == nil {
		return errors.New("vmqual material: persisted owner missing")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return errors.New("vmqual material: persisted owner is not P-256")
	}
	defer key.D.SetInt64(0)
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return err
	}
	publicRef, err := write("owner-public.pem", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), 0644)
	if err != nil {
		return err
	}
	payload.Version, payload.RunID, payload.Artifacts = 1, input.Network.RunID, input.Artifacts
	payload.IssuedAt, payload.ExpiresAt = owner.IssuedAt, owner.IssuedAt.Add(24*time.Hour)
	payload.CandidatePlan.PrivateMaterialDirectory = filepath.Join(root, "candidates")
	payload.CandidatePlan.IssuedAt = payload.IssuedAt
	payload.CandidatePlan.ExpiresAt = payload.ExpiresAt
	payload.CandidatePlan.BootstrapExpiresAt = payload.ExpiresAt
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	payloadRef, err := write("control-payload.json", encoded, 0644)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(append([]byte(qualificationControlDomain), encoded...))
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return err
	}
	outer, err := json.Marshal(qualificationControlDeclaration{OwnerKey: publicRef, Payload: payloadRef, Signature: signature})
	if err != nil {
		return err
	}
	declaration, err := write("control-declaration.pending.json", outer, 0600)
	if err != nil {
		return err
	}
	pins := map[string]vmimage.GuestArtifact{}
	for _, artifact := range input.Artifacts {
		pins[artifact.Component] = artifact
	}
	admitted, err := loadQualificationControlDeclaration(declaration.Source, input.Network, input.Architecture, pins)
	if err != nil {
		return fmt.Errorf("vmqual material generated admission: %w", err)
	}
	defer admitted.Clear()
	if err := validateLocalMaterialActions(admitted); err != nil {
		return fmt.Errorf("vmqual material runtime actions: %w", err)
	}
	run, err := json.Marshal(input.RunDeclaration)
	if err != nil {
		return err
	}
	runRef, err := write("run-declaration.json", run, 0644)
	if err != nil {
		return err
	}
	if _, err := vmcontrolseed.LoadRunDeclaration(runRef.Source); err != nil {
		return err
	}
	network, err := json.Marshal(input.Network)
	if err != nil {
		return err
	}
	if _, err := write("network-plan.json", network, 0644); err != nil {
		return err
	}
	metadata := fmt.Sprintf("Local offline admission only; guest qualification remains pending.\nTS_VM_STATE_ROOT=%s\nTS_VM_CONTROL_DECLARATION_FILE=%s\nTS_VM_RUN_DECLARATION_FILE=%s\nNetwork run ID: %s\nUse the exact network-plan.json and artifact records from the input.\n", filepath.Join(root, "state"), filepath.Join(root, "control-declaration.json"), runRef.Source, input.Network.RunID)
	if _, err := write("README.generated", []byte(metadata), 0644); err != nil {
		return err
	}
	return os.Rename(declaration.Source, filepath.Join(root, "control-declaration.json"))
}

func validateLocalMaterialActions(admitted *qualificationControlAdmission) error {
	config := admitted.source.config
	stores := make([]string, 0, len(config.Stores))
	for name := range config.Stores {
		stores = append(stores, name)
	}
	members := slices.Clone(config.Members)
	logical := map[string]string{}
	for i := range members {
		logical[members[i].MemberID] = members[i].HostID
		members[i].MemberID = members[i].HostID
	}
	plans := slices.Clone(config.Actions)
	for i := range plans {
		plans[i].Handoffs = slices.Clone(plans[i].Handoffs)
		for j := range plans[i].Handoffs {
			plans[i].Handoffs[j].MemberID = logical[plans[i].Handoffs[j].MemberID]
		}
		plans[i].Checks = slices.Clone(plans[i].Checks)
		for j := range plans[i].Checks {
			plans[i].Checks[j].Members = slices.Clone(plans[i].Checks[j].Members)
			for k, id := range plans[i].Checks[j].Members {
				plans[i].Checks[j].Members[k] = logical[id]
			}
		}
	}
	return bootstrap.ValidateLiveControlRuntimeDeclarations(stores, members, plans)
}
