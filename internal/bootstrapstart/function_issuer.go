package bootstrapstart

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"golang.org/x/sys/unix"
)

// RootFunctionIssuer retains the original current sealed source in root.
type RootFunctionIssuer struct {
	Startup     bootstrap.DerivedStartupAuthority
	Anchor      bootstrap.VerifiedBootstrapAnchor
	Issuer      *bootstrapmaterial.ControllerIssuer
	OperatorJWT []byte
	BrokerCA    []byte
	reader      *CurrentFounderAuthorityReader
	accepted    AcceptedIdentity
	authority   RuntimeAuthority
	original    context.Context
	deadline    time.Time
}

func (issuer RootFunctionIssuer) ExpiresAt() time.Time { return issuer.deadline }

// CheckOriginal seals retained lifetimes locally after the final awaited guard.
func (issuer RootFunctionIssuer) CheckOriginal(ctx context.Context) error {
	if os.Geteuid() != 0 || ctx == nil || issuer.original == nil || issuer.original.Err() != nil || ctx.Err() != nil || issuer.reader == nil || issuer.Issuer == nil || !issuer.Startup.IsVerified() ||
		!time.Now().Before(issuer.deadline) || !time.Now().Before(issuer.Issuer.ExpiresAt()) || issuer.deadline.After(issuer.authority.ExpiresAt()) || issuer.deadline.After(issuer.Startup.ExpiresAt()) || issuer.Issuer.ExpiresAt().After(issuer.deadline) {
		return ErrAdmission
	}
	return nil
}

// Guard retains the first founder selection and its deadline across rereads.
func (issuer RootFunctionIssuer) Guard(ctx context.Context) error {
	if err := issuer.CheckOriginal(ctx); err != nil {
		return err
	}
	ctx, cancel := context.WithDeadline(ctx, issuer.deadline)
	stop := context.AfterFunc(issuer.original, cancel)
	defer cancel()
	defer stop()
	current, err := issuer.reader.ReadRuntimeAuthority(ctx, issuer.accepted, time.Now().UTC())
	if err != nil || current.identity != issuer.authority.identity || current.planDigest != issuer.authority.planDigest || current.selectionDigest != issuer.authority.selectionDigest || current.expires.Before(issuer.deadline) {
		return ErrAdmission
	}
	if err := issuer.Startup.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		return err
	}
	return issuer.CheckOriginal(ctx)
}

// ReadRootFunctionIssuer never takes source authority or key bytes from the caller.
func (reader *CurrentFounderAuthorityReader) ReadRootFunctionIssuer(ctx context.Context, accepted AcceptedIdentity, serviceUID, serviceGID uint32) (RootFunctionIssuer, error) {
	if os.Geteuid() != 0 || reader == nil || ctx == nil || serviceUID == 0 || serviceGID == 0 {
		return RootFunctionIssuer{}, ErrAdmission
	}
	authority, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC())
	if err != nil {
		return RootFunctionIssuer{}, err
	}
	if authority.derived == nil {
		return RootFunctionIssuer{}, ErrAdmission
	}
	startup, ok := authority.derived.Authority(accepted.Slot)
	if !ok || startup.VerifyCurrent(ctx, time.Now().UTC()) != nil {
		return RootFunctionIssuer{}, ErrAdmission
	}
	var record bootstrapmaterial.Record
	if json.Unmarshal(startup.MaterialRecord(), &record, json.RejectUnknownMembers(true)) != nil {
		return RootFunctionIssuer{}, ErrMaterial
	}
	directory, err := openMaterialDirectory(MaterialDirectory, serviceUID, serviceGID, 0o700, false)
	if err != nil {
		return RootFunctionIssuer{}, err
	}
	defer unix.Close(directory)
	files := map[string][]byte{}
	defer func() {
		for _, body := range files {
			clear(body)
		}
	}()
	read := func(name string) ([]byte, error) {
		for _, file := range record.Files {
			if file.Name != name {
				continue
			}
			uid, gid := serviceUID, serviceGID
			if name == "controller-account-signer.seed" || name == "controller-tls-issuer-key.pem" {
				uid, gid = 0, 0
			}
			body, err := readMaterial(directory, name, uid, gid, file.SHA256, file.MaxBytes)
			if err == nil {
				files[name] = body
			}
			return body, err
		}
		return nil, ErrMaterial
	}
	issuer, err := bootstrapmaterial.LoadStartupControllerIssuer(ctx, startup, read, time.Now().UTC())
	if err != nil {
		return RootFunctionIssuer{}, err
	}
	deadline := startup.ExpiresAt()
	if authority.ExpiresAt().Before(deadline) {
		deadline = authority.ExpiresAt()
	}
	if err := issuer.RestrictExpiry(deadline); err != nil {
		issuer.Wipe()
		return RootFunctionIssuer{}, err
	}
	result := RootFunctionIssuer{Startup: startup, Anchor: authority.Anchor(), Issuer: issuer, OperatorJWT: bytes.Clone(files["operator.jwt"]), BrokerCA: bytes.Clone(files["ca.pem"]), reader: reader, accepted: accepted.Clone(), authority: authority, original: ctx, deadline: deadline}
	if err := result.Guard(ctx); err != nil {
		issuer.Wipe()
		return RootFunctionIssuer{}, err
	}
	return result, nil
}
