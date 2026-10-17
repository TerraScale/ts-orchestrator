package bootstrap

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

const netBirdOriginBucket = "gru-1-head"
const netBirdOriginChainObject = "orchestrator/foundation/v1/root-chain.json"
const netBirdOriginGrantObject = "foundation-scope-v1.json"
const netBirdOriginGrantLimit = 128 << 10

// NetBirdJournalOriginReference pins existing immutable prerequisite objects;
// it is public evidence and grants no authority to select a successor source.
type NetBirdJournalOriginReference struct {
	Namespace       string `json:"namespace"`
	GrantObject     string `json:"grantObject"`
	GrantSHA256     string `json:"grantSha256"`
	RootChainSHA256 string `json:"rootChainSha256"`
}

func (reference NetBirdJournalOriginReference) Validate() error {
	prefix, ok := strings.CutSuffix(reference.GrantObject, "/"+netBirdOriginGrantObject)
	if !ledgerIDPattern.MatchString(reference.Namespace) || len(prefix) > 128 || !ok || !validLedgerPrefix(prefix) ||
		!validDigest(reference.GrantSHA256) || !validDigest(reference.RootChainSHA256) {
		return errors.New("NetBird journal origin lacks its exact immutable signed grant and root chain references")
	}
	return nil
}

// NetBirdJournalOriginDocuments contains public descriptive signed bytes only.
// Consumers must independently bind source, purpose and protected operations;
// these documents cannot authorize current actions or mint a current purpose.
type NetBirdJournalOriginDocuments struct {
	GrantWire     []byte
	RootChainWire []byte
}

// ReadNetBirdJournalOrigin authenticates exact existing OCI objects and their
// historical signature interval without adopting any current trust floor.
func ReadNetBirdJournalOrigin(ctx context.Context, factory *ociclient.Factory, genesis trust.Keyring, reference NetBirdJournalOriginReference, acceptedAt time.Time) (NetBirdJournalOriginDocuments, error) {
	var zero NetBirdJournalOriginDocuments
	if ctx == nil || factory == nil || len(genesis) == 0 || reference.Validate() != nil || acceptedAt.IsZero() || acceptedAt.After(time.Now()) {
		return zero, errors.New("NetBird journal origin requires authenticated OCI, independent roots and its original accepted instant")
	}
	genesis = maps.Clone(genesis)
	for id, key := range genesis {
		genesis[id] = bytes.Clone(key)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tenancy, err := factory.Provider().TenancyOCID()
	if err != nil || tenancy == "" {
		return zero, errors.Join(errors.New("NetBird journal origin has no authenticated tenancy"), err)
	}
	home, err := factory.ForRegion("sa-saopaulo-1")
	if err != nil {
		return zero, err
	}
	client, err := home.ObjectStorage()
	if err != nil {
		return zero, err
	}
	namespace, err := client.GetNamespace(ociclient.RequestContext(ctx), objectstorage.GetNamespaceRequest{CompartmentId: new(tenancy)})
	if err != nil || namespace.Value == nil || *namespace.Value != reference.Namespace {
		return zero, errors.Join(errors.New("NetBird journal origin namespace differs from the authenticated tenancy"), err)
	}
	read := func(name string, limit int64) ([]byte, error) {
		response, err := client.GetObject(ociclient.RequestContext(ctx), objectstorage.GetObjectRequest{
			NamespaceName: new(reference.Namespace), BucketName: new(netBirdOriginBucket), ObjectName: new(name)})
		if err != nil {
			return nil, err
		}
		if response.Content == nil {
			return nil, errors.New("NetBird journal original signed object has no content")
		}
		defer response.Content.Close()
		wire, err := io.ReadAll(io.LimitReader(response.Content, limit+1))
		if err != nil || len(wire) == 0 || int64(len(wire)) > limit {
			return nil, errors.Join(errors.New("NetBird journal original signed object is unreadable or oversized"), err)
		}
		return wire, nil
	}
	chainWire, err := read(netBirdOriginChainObject, trust.MaxRootChainBytes)
	if err != nil {
		return zero, err
	}
	grantWire, err := read(reference.GrantObject, netBirdOriginGrantLimit)
	if err != nil {
		return zero, err
	}
	if digestBytes(chainWire) != reference.RootChainSHA256 || digestBytes(grantWire) != reference.GrantSHA256 {
		return zero, errors.New("NetBird journal original signed objects changed or selected a successor")
	}
	envelope, err := trust.DecodeEnvelope(grantWire)
	if err != nil {
		return zero, err
	}
	chain, err := trust.DecodeRootChain(chainWire)
	if err != nil {
		return zero, err
	}
	roots, err := trust.VerifyRootChain(genesis, trust.ChainIdentity{DeploymentID: envelope.Scope.DeploymentID, Cell: "gru", Environment: "production"}, chain)
	if err != nil {
		return zero, err
	}
	expected := trust.Scope{Domain: "terrascale.foundation.scope", DeploymentID: envelope.Scope.DeploymentID,
		Cell: "GRU", Environment: "production", Role: "foundation", Slot: envelope.Scope.Slot}
	payload, err := trust.VerifyHistorical(envelope, expected, roots.Current, BootstrapAnchorTrustPolicy())
	if err != nil {
		return zero, err
	}
	var grant struct {
		TenancyID string `json:"tenancyId"`
	}
	if json.Unmarshal(payload, &grant) != nil || grant.TenancyID != tenancy || acceptedAt.Before(envelope.IssuedAt) || !acceptedAt.Before(envelope.ExpiresAt) {
		return zero, errors.New("NetBird journal original grant differs from its authenticated tenancy or original signed interval")
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return NetBirdJournalOriginDocuments{GrantWire: grantWire, RootChainWire: chainWire}, nil
}
