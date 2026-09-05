//go:build sandboxvm

package vmqualruntime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
)

type qualificationMembershipIdentity struct {
	PrivatePEM []byte
	KeyID      string
	PublicKey  string
}

func newQualificationMembershipIdentity() (*qualificationMembershipIdentity, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	defer private.D.SetInt64(0)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(der)
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	keyID, public, err := directory.RegionalRuntimeMembershipPublicKeyFromPEM(encoded)
	if err != nil {
		zeroBytes(encoded)
		return nil, err
	}
	return &qualificationMembershipIdentity{PrivatePEM: encoded, KeyID: keyID, PublicKey: public}, nil
}

// QualificationMembershipPins returns preissued public identities keyed by the
// declared guest instance. These are enrollment inputs, not observed liveness.
func (factory *firecrackerFactory) QualificationMembershipPins(ctx context.Context) (map[string]string, error) {
	if ctx == nil {
		return nil, errors.New("vmqual: membership pin context missing")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	services, ok := factory.services.(*qualificationRuntimeServices)
	if !ok {
		return nil, errors.New("vmqual: membership issuer unavailable")
	}
	services.mu.Lock()
	defer services.mu.Unlock()
	if services.closed || services.natsAuthority == nil {
		return nil, errors.New("vmqual: membership issuer closed")
	}
	pins := make(map[string]string, len(services.natsAuthority.memberships))
	for host, identity := range services.natsAuthority.memberships {
		pins[host] = identity.PublicKey
	}
	return pins, nil
}
