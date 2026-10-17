package materialsource

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
	ocisecrets "github.com/oracle/oci-go-sdk/v65/secrets"
	ocivault "github.com/oracle/oci-go-sdk/v65/vault"
	"golang.org/x/sys/unix"
)

var ErrLinkDeliveryPending = errors.New("home has not published this region's Link delivery")

// IssueRegionalLink consumes public recipient inventory and only local home
// private sources. The recipient's founder escrow is never read.
func IssueRegionalLink(ctx context.Context, home *ColdStartMaterial, homeLink *LinkSource, recipient bootstrap.LinkRecipient, grant region.VerifiedBootstrapMaterial, objects bootstrapstart.FounderSelectionObjectWriter, management bootstrapmaterial.VaultClient, bundles EscrowClient, directory string, now time.Time) (*LinkSource, error) {
	if home == nil || homeLink == nil || homeLink.source == nil || objects == nil || management == nil || bundles == nil || now.IsZero() || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || overlappingSourceDirectories(directory, home.directory) || overlappingSourceDirectories(directory, homeLink.source.directory) || recipient.VerifyCurrent(ctx, now) != nil {
		return nil, ErrMaterialSource
	}
	inputs := &linkInputs{home: home, homeLink: homeLink, recipient: new(recipient), recipientGrant: grant, regionalDigest: recipient.SourceSHA256(), homeDigest: recipient.HomeSHA256(), homeLinkDigest: digestWire(homeLink.source.archive.Files["material.json"])}
	if err := inputs.verify(ctx); err != nil {
		return nil, err
	}
	scope := sha256.Sum256([]byte(recipient.InstallationID() + "\x00" + grant.Config().Cell + "\x00spoke-link-v1\x00" + recipient.BindingSHA256()))
	source := &ColdStartMaterial{actor: home.actor, grant: grant, objects: objects, directory: directory, kind: "spoke-link-v1", binding: recipient.BindingSHA256(), link: inputs, secretName: "ts-bootstrap-source-link-" + hex.EncodeToString(scope[:16]), key: recipient.LinkObjectKey()}
	source, err := resolveSource(ctx, source, management, bundles, now)
	if err != nil {
		return nil, err
	}
	record, err := bootstrapmaterial.LoadLink(directory, now)
	if err != nil {
		return nil, err
	}
	return &LinkSource{source: source, record: record}, nil
}

// PublishRegionalLink delivers only host leaf material to the exact signed
// regional Vault, then checkpoints its authenticated public delivery in the CAS.
func (link *LinkSource) PublishRegionalLink(ctx context.Context, target bootstrapmaterial.VaultTarget, management bootstrapmaterial.VaultClient, bundles bootstrapmaterial.BundleClient, now time.Time) (bootstrapmaterial.Publication, error) {
	if link == nil || link.source == nil || link.source.link == nil || link.source.link.recipient == nil {
		return bootstrapmaterial.Publication{}, ErrMaterialSource
	}
	publication, err := link.Provision(ctx, target, management, bundles, now)
	if err != nil {
		return bootstrapmaterial.Publication{}, err
	}
	source := link.source
	recipient := *source.link.recipient
	evidence := link.evidence(publication)
	payload, err := bootstrap.LinkDeliveryPayload(evidence)
	if err != nil {
		return bootstrapmaterial.Publication{}, err
	}
	next := source.state
	if len(next.Delivery) > 0 {
		prior, err := bootstrap.VerifyLinkDelivery(ctx, recipient, next.Delivery, now)
		if err != nil || !bytes.Equal(prior, payload) {
			return bootstrapmaterial.Publication{}, ErrMaterialSource
		}
		return publication, nil
	}
	key := source.link.home.archive.Files["founder-ledger.key"]
	next.Delivery, err = bootstrap.SignLinkDelivery(recipient, payload, ed25519.PrivateKey(key), source.state.StartedAt, recipient.ExpiresAt())
	if err != nil {
		return bootstrapmaterial.Publication{}, err
	}
	etag, err := source.write(ctx, next, source.etag)
	if err != nil {
		return bootstrapmaterial.Publication{}, err
	}
	source.state, source.etag = next, etag
	return publication, nil
}

func (link *LinkSource) evidence(publication bootstrapmaterial.Publication) bootstrap.RegionalLinkEvidence {
	return bootstrap.RegionalLinkEvidence{SourceObjectKey: link.source.key, SourceSHA256: link.source.state.Reference.SHA256, MaterialRecord: bytes.Clone(link.source.archive.Files["material.json"]), Journal: bytes.Clone(link.source.state.Journal), References: publication.LinkGenerationReferences(), Delivery: bytes.Clone(link.source.state.Delivery)}
}

// StartupLink exposes the same public proof for home initial binding and reboot.
func (link *LinkSource) StartupLink(ctx context.Context, template bootstrap.VerifiedStartupTemplate, now time.Time) (bootstrap.VerifiedStartupLink, error) {
	if link == nil || link.source == nil || link.source.verifySource(ctx) != nil || link.source.publication.SchemaVersion != 1 {
		return bootstrap.VerifiedStartupLink{}, ErrMaterialSource
	}
	return bootstrap.VerifyStartupLink(ctx, template, link.source.objects, link.evidence(link.source.publication), now)
}

type VerifiedRegionalLink struct {
	regional    VerifiedColdStartMaterial
	proof       bootstrap.VerifiedStartupLink
	directory   string
	record      bootstrapmaterial.LinkRecord
	publication bootstrapmaterial.Publication
}

func (link VerifiedRegionalLink) IsVerified() bool {
	return link.regional.IsVerified() && link.proof.IsVerified() && link.directory != ""
}
func (link VerifiedRegionalLink) Record() bootstrapmaterial.LinkRecord {
	record := link.record
	record.Record = cloneRecord(record.Record)
	return record
}
func (link VerifiedRegionalLink) Publication() bootstrapmaterial.Publication {
	return clonePublication(link.publication)
}
func (link VerifiedRegionalLink) Grant() region.VerifiedBootstrapMaterial {
	return link.regional.Grant()
}
func (link VerifiedRegionalLink) Proof() bootstrap.VerifiedStartupLink { return link.proof }
func (link VerifiedRegionalLink) VerifyCurrent(ctx context.Context) error {
	if !link.IsVerified() || link.regional.VerifyCurrent(ctx) != nil || link.proof.VerifyCurrent(ctx, time.Now()) != nil {
		return ErrMaterialSource
	}
	evidence := link.proof.Evidence()
	metadata, err := os.ReadFile(filepath.Join(link.directory, "material.json"))
	if err != nil || !bytes.Equal(metadata, evidence.MaterialRecord) {
		return ErrMaterialSource
	}
	return bootstrapmaterial.ValidateLinkPublication(link.directory, link.publication, evidence.Journal, time.Now())
}

// ResolveRegionalLink reads public home delivery and the recipient's exact
// version-one Vault leaves. It cannot fetch any home private source escrow.
func ResolveRegionalLink(ctx context.Context, regional VerifiedColdStartMaterial, recipient bootstrap.LinkRecipient, objects bootstrap.ObjectStorageClient, bundles bootstrapmaterial.BundleClient, directory string, now time.Time) (VerifiedRegionalLink, error) {
	deny := func() (VerifiedRegionalLink, error) { return VerifiedRegionalLink{}, ErrMaterialSource }
	if !regional.IsVerified() || objects == nil || bundles == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || overlappingSourceDirectories(directory, regional.source.directory) || regional.VerifyCurrent(ctx) != nil || recipient.VerifyCurrent(ctx, now) != nil || recipient.GrantDigest() != digestWire(regional.Grant().FoundationGrantWire()) || recipient.SourceSHA256() != regional.Publication().MaterialSHA256 {
		return deny()
	}
	ctx, cancel := context.WithDeadline(ctx, recipient.ExpiresAt())
	defer cancel()
	domain := recipient.StorageDomain()
	response, err := objects.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{NamespaceName: new(domain.Namespace), BucketName: new(domain.HeadBucket), ObjectName: new(recipient.LinkObjectKey())})
	if service, ok := common.IsServiceError(err); ok && service.GetHTTPStatusCode() == 404 {
		return VerifiedRegionalLink{}, ErrLinkDeliveryPending
	}
	if err != nil {
		return VerifiedRegionalLink{}, err
	}
	if response.Content == nil {
		return deny()
	}
	defer response.Content.Close()
	wire, err := io.ReadAll(io.LimitReader(response.Content, 2<<20))
	if err != nil || len(wire) >= 2<<20 {
		return deny()
	}
	var state struct {
		Delivery []byte `json:"delivery"`
	}
	if json.Unmarshal(wire, &state) != nil {
		return deny()
	}
	if len(state.Delivery) == 0 {
		return VerifiedRegionalLink{}, ErrLinkDeliveryPending
	}
	payload, err := bootstrap.VerifyLinkDelivery(ctx, recipient, state.Delivery, now)
	if err != nil {
		return deny()
	}
	var evidence bootstrap.RegionalLinkEvidence
	if json.Unmarshal(payload, &evidence, json.RejectUnknownMembers(true)) != nil || len(evidence.Delivery) > 0 {
		return deny()
	}
	evidence.Delivery = bytes.Clone(state.Delivery)
	template := recipient.RegionalSourceTemplate()
	proof, err := bootstrap.VerifyStartupLink(ctx, template, objects, evidence, now)
	if err != nil {
		return deny()
	}
	var record bootstrapmaterial.LinkRecord
	if json.Unmarshal(evidence.MaterialRecord, &record, json.RejectUnknownMembers(true)) != nil {
		return deny()
	}
	publication, err := linkPublication(evidence, template.VaultTarget())
	if err != nil {
		return deny()
	}
	if err := restoreRegionalLink(ctx, proof, record, publication, bundles, directory, now); err != nil {
		return VerifiedRegionalLink{}, err
	}
	result := VerifiedRegionalLink{regional: regional, proof: proof, directory: directory, record: record, publication: publication}
	if err := result.VerifyCurrent(ctx); err != nil {
		return deny()
	}
	return result, nil
}

func linkPublication(evidence bootstrap.RegionalLinkEvidence, target bootstrap.StartupVaultTarget) (bootstrapmaterial.Publication, error) {
	var journal struct {
		Entries []struct {
			Name       string `json:"name"`
			FileName   string `json:"fileName"`
			SecretOCID string `json:"secretOcid"`
		} `json:"entries"`
	}
	if json.Unmarshal(evidence.Journal, &journal) != nil {
		return bootstrapmaterial.Publication{}, ErrMaterialSource
	}
	result := bootstrapmaterial.Publication{SchemaVersion: 1, Target: bootstrapmaterial.VaultTarget{CompartmentOCID: target.CompartmentOCID, VaultOCID: target.VaultOCID, KMSKeyOCID: target.KMSKeyOCID}, MaterialSHA256: digestWire(evidence.MaterialRecord)}
	for _, ref := range evidence.References {
		i := slices.IndexFunc(journal.Entries, func(entry struct {
			Name       string `json:"name"`
			FileName   string `json:"fileName"`
			SecretOCID string `json:"secretOcid"`
		}) bool {
			return entry.FileName == ref.TargetFile && entry.SecretOCID == ref.SecretOCID
		})
		if i < 0 {
			return bootstrapmaterial.Publication{}, ErrMaterialSource
		}
		result.References = append(result.References, bootstrapmaterial.PublicReference{SecretName: journal.Entries[i].Name, Reference: ref})
	}
	return result, nil
}

func restoreRegionalLink(ctx context.Context, proof bootstrap.VerifiedStartupLink, record bootstrapmaterial.LinkRecord, publication bootstrapmaterial.Publication, bundles bootstrapmaterial.BundleClient, directory string, now time.Time) error {
	ctx, cancel := context.WithDeadline(ctx, record.ExpiresAt)
	defer cancel()
	evidence := proof.Evidence()
	guard := func() error {
		if err := proof.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
			return err
		}
		if err := bootstrapmaterial.GuardPublication(ctx); err != nil {
			return err
		}
		if !time.Now().Before(record.ExpiresAt) {
			return ErrMaterialSource
		}
		return ctx.Err()
	}
	validate := func() error {
		if err := bootstrapmaterial.ValidateLinkPublication(directory, publication, evidence.Journal, time.Now().UTC()); err != nil {
			return err
		}
		return guard()
	}
	if _, err := os.Lstat(directory); err == nil {
		return validate()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent, err := os.MkdirTemp(filepath.Dir(directory), ".regional-link-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(parent)
	for _, ref := range evidence.References {
		if err := guard(); err != nil {
			return err
		}
		response, err := bundles.GetSecretBundle(ociclient.RequestContext(ctx), ocisecrets.GetSecretBundleRequest{SecretId: new(ref.SecretOCID), VersionNumber: new(int64(1))})
		if err != nil || response.SecretId == nil || *response.SecretId != ref.SecretOCID || response.VersionNumber == nil || *response.VersionNumber != 1 {
			return ErrMaterialSource
		}
		content, ok := response.SecretBundleContent.(ocisecrets.Base64SecretBundleContentDetails)
		if !ok || content.Content == nil || len(*content.Content) > base64.StdEncoding.EncodedLen(int(ref.MaxBytes)) {
			return ErrMaterialSource
		}
		body, err := base64.StdEncoding.Strict().DecodeString(*content.Content)
		if err != nil || int64(len(body)) != ref.MaxBytes || digestWire(body) != ref.SHA256 {
			clear(body)
			return ErrMaterialSource
		}
		err = writeSourceFile(filepath.Join(parent, ref.TargetFile), body)
		clear(body)
		if err != nil {
			return err
		}
	}
	for name, body := range map[string][]byte{"material.json": evidence.MaterialRecord, "READY": []byte(digestWire(evidence.MaterialRecord) + "\n"), "publication.json": evidence.Journal} {
		if err := writeSourceFile(filepath.Join(parent, name), body); err != nil {
			return err
		}
	}
	if err := bootstrapmaterial.ValidateLinkPublication(parent, publication, evidence.Journal, time.Now().UTC()); err != nil {
		return err
	}
	if err := syncSourceDirectory(parent); err != nil {
		return err
	}
	if err := guard(); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, parent, unix.AT_FDCWD, directory, unix.RENAME_NOREPLACE); err != nil {
		if !errors.Is(err, unix.EEXIST) {
			return err
		}
		return validate()
	}
	if err := syncSourceDirectory(filepath.Dir(directory)); err != nil {
		return err
	}
	return guard()
}

// ReconcileHomeLinks retries each independently admitted region. Pending source
// registration never changes the home's own ready Link or another delivery.
func ReconcileHomeLinks(ctx context.Context, home *ColdStartMaterial, homeLink *LinkSource, homeProof bootstrap.VerifiedRegionalSource, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring, factory *ociclient.Factory, directory string, now time.Time) (map[string]bootstrapmaterial.Publication, error) {
	result := make(map[string]bootstrapmaterial.Publication)
	if home == nil || homeLink == nil || homeLink.source == nil || factory == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || homeProof.VerifyCurrent(ctx, now) != nil || !bytes.Equal(homeProof.MaterialRecord(), home.archive.Files["material.json"]) || home.grant.Config().Cell != "gru" || anchor.Anchor().Cell != oci.RegionGRU {
		return result, ErrMaterialSource
	}
	if overlappingSourceDirectories(directory, home.directory) || overlappingSourceDirectories(directory, homeLink.source.directory) {
		return result, ErrMaterialSource
	}
	scope, err := anchor.FoundationScope()
	if err != nil {
		return result, err
	}
	footprint, err := region.NewSignedFootprint(home.objects, anchor, roots, scope.TenancyID)
	if err != nil {
		return result, err
	}
	approved, err := footprint.AuthorizedRegions(ctx)
	if err != nil {
		return result, err
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return result, err
	}
	homeFactory, err := factory.ForRegion("sa-saopaulo-1")
	if err != nil {
		return result, err
	}
	escrowManagement, escrowBundles, err := linkVaultClients(homeFactory)
	if err != nil {
		return result, err
	}
	var pending []error
	for _, intent := range approved.Regions {
		cell, ok := intent.Plan["cell"].(string)
		if !ok || cell == "GRU" {
			continue
		}
		issue := func() error {
			template, err := bootstrap.VerifyBoundRegionalStartupTemplate(ctx, factory, home.grant.FoundationGrantWire(), roots, anchor, oci.Region(cell), now)
			if err != nil {
				return err
			}
			regional, err := bootstrap.LoadRegionalSource(ctx, template, home.objects, now)
			if err != nil {
				return fmt.Errorf("%w: %s public inventory unavailable", ErrLinkDeliveryPending, cell)
			}
			recipient, err := bootstrap.VerifyLinkRecipient(ctx, regional, homeProof, now)
			if err != nil {
				return err
			}
			grant, err := footprint.AuthorizedBootstrapMaterial(ctx, cell)
			if err != nil {
				return err
			}
			link, err := IssueRegionalLink(ctx, home, homeLink, recipient, grant, home.objects, escrowManagement, escrowBundles, filepath.Join(directory, strings.ToLower(cell)), now)
			if err != nil {
				return err
			}
			regionalFactory, err := factory.ForRegion(grant.Config().Region)
			if err != nil {
				return err
			}
			management, bundles, err := linkVaultClients(regionalFactory)
			if err != nil {
				return err
			}
			target := recipient.VaultTarget()
			publication, err := link.PublishRegionalLink(ctx, bootstrapmaterial.VaultTarget{CompartmentOCID: target.CompartmentOCID, VaultOCID: target.VaultOCID, KMSKeyOCID: target.KMSKeyOCID}, management, bundles, now)
			if err != nil {
				return err
			}
			result[strings.ToLower(cell)] = publication
			return nil
		}
		if err := issue(); err != nil {
			pending = append(pending, fmt.Errorf("regional Link %s: %w", cell, err))
		}
	}
	return result, errors.Join(pending...)
}

func linkVaultClients(factory *ociclient.Factory) (*ocivault.VaultsClient, *ocisecrets.SecretsClient, error) {
	management, err := ocivault.NewVaultsClientWithConfigurationProvider(factory.Provider())
	if err != nil {
		return nil, nil, err
	}
	management.SetRegion(factory.Region())
	factory.Configure(&management.BaseClient, ociclient.ServiceVault)
	bundles, err := vaultsecret.SecretsClient(factory)
	if err != nil {
		return nil, nil, err
	}
	return &management, &bundles, nil
}
