//go:build linux

package hostsecrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const ownershipName = ".host-secrets-ownership.json"

type ownershipRecord struct {
	SeedDigest     string `json:"seedDigest"`
	ManifestDigest string `json:"manifestDigest"`
	User           string `json:"user"`
	UID            int    `json:"uid"`
	GID            int    `json:"gid"`
}

// AdmitServiceOwnershipFile must be called by ts-node only after the
// bootstrap manifest has been authenticated, durably admitted, and its exact
// service account created. manifestDigest is that admitted manifest's bare
// SHA-256. The caller must hold its node authority/retirement lock throughout
// the handoff and must never call initial bootstrap after runtime retirement.
// An absent fixed seed returns os.ErrNotExist for non-OCI qualification.
func AdmitServiceOwnershipFile(ctx context.Context, path, serviceUser, manifestDigest string) error {
	if ctx == nil || path != SeedPath || (serviceUser != OrchestratorUser && serviceUser != TerraBaseUser) || !digestPattern.MatchString(manifestDigest) {
		return ErrSeed
	}
	if os.Geteuid() != 0 {
		return ErrUnsupported
	}
	root, err := openDirectory(credentialRoot, 0, false)
	if errors.Is(err, unix.ENOENT) {
		return os.ErrNotExist
	}
	if err != nil {
		return ErrOwnership
	}
	defer unix.Close(root)
	body, err := readAt(root, "host-secrets.json", MaxSeedBytes, 0, false)
	if errors.Is(err, unix.ENOENT) {
		return os.ErrNotExist
	}
	if err != nil {
		return ErrOwnership
	}
	seed, err := ParseSeed(body)
	if err != nil {
		return err
	}
	account, err := user.Lookup(serviceUser)
	if err != nil {
		return ErrOwnership
	}
	uid, e1 := strconv.Atoi(account.Uid)
	gid, e2 := strconv.Atoi(account.Gid)
	if e1 != nil || e2 != nil || uid <= 0 || gid <= 0 {
		return ErrOwnership
	}
	p, err := prepare(ctx, root, seed, 0)
	if err != nil {
		return err
	}
	defer p.close()
	return p.admitOwnership(ctx, ownershipRecord{SeedDigest: seedDigest(seed), ManifestDigest: manifestDigest, User: serviceUser, UID: uid, GID: gid})
}

func entryService(entry Entry) string {
	switch entry.Destination {
	case "/etc/terrascale/terrabase/key.pem", "/etc/terrascale/terrabase/transition/receipt-signer.key":
		return TerraBaseUser
	case "/etc/terrascale/engine-observer/client.key", "/etc/terrascale/placement/engine-client.key", "/etc/terrascale/placement/host.nkey", "/etc/terrascale/placement/nats-client.key", "/etc/terrascale/database/host.nkey", "/etc/terrascale/database/lifecycle.nkey", "/etc/terrascale/database/nats-client.key":
		return OrchestratorUser
	}
	if strings.HasPrefix(entry.Destination, "/etc/terrascale/orchestrator/") {
		return OrchestratorUser
	}
	return ""
}
func (p *publication) entryOwnership(entry Entry) *ownershipRecord {
	switch entryService(entry) {
	case OrchestratorUser:
		return p.ownership
	case TerraBaseUser:
		return p.engineOwnership
	default:
		return nil
	}
}
func ownershipFile(service string) string {
	if service == TerraBaseUser {
		return ".host-secrets-terrabase-ownership.json"
	}
	return ownershipName
}
func (p *publication) loadOwnership() error {
	for _, service := range []string{OrchestratorUser, TerraBaseUser} {
		if err := p.loadServiceOwnership(service); err != nil {
			return err
		}
	}
	if p.ownership != nil && p.engineOwnership != nil && p.ownership.ManifestDigest != p.engineOwnership.ManifestDigest {
		return ErrJournal
	}
	return nil
}
func (p *publication) loadServiceOwnership(service string) error {
	body, err := readAt(p.root, ownershipFile(service), 4096, p.uid, true)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return ErrJournal
	}
	var record ownershipRecord
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&record) != nil || decoder.Decode(&struct{}{}) != io.EOF || !p.validOwnership(record) || record.User != service {
		return ErrJournal
	}
	if unix.Fsync(p.root) != nil {
		return ErrJournal
	}
	if service == TerraBaseUser {
		p.engineOwnership = &record
	} else {
		p.ownership = &record
	}
	return nil
}
func (p *publication) validOwnership(record ownershipRecord) bool {
	return (record.User == OrchestratorUser || record.User == TerraBaseUser) && record.UID > 0 && record.GID > 0 && uint64(record.UID) < 1<<32 && uint64(record.GID) < 1<<32 && record.SeedDigest == seedDigest(p.seed) && digestPattern.MatchString(record.ManifestDigest)
}
func (p *publication) admitOwnership(ctx context.Context, record ownershipRecord) error {
	if !p.validOwnership(record) {
		return ErrOwnership
	}
	for _, accepted := range []*ownershipRecord{p.ownership, p.engineOwnership} {
		if accepted != nil && accepted.ManifestDigest != record.ManifestDigest {
			return ErrJournal
		}
	}
	stored := p.ownership
	if record.User == TerraBaseUser {
		stored = p.engineOwnership
	}
	if stored != nil {
		if *stored != record {
			return ErrJournal
		}
	} else {
		// All bytes must already be present and verified before admitting a new
		// owner. Handoff never retrieves or invents missing credentials.
		for _, entry := range p.seed.Entries {
			ready, err := p.ready(entry)
			if err != nil {
				return err
			}
			if !ready {
				return ErrPublish
			}
		}
		body, _ := json.Marshal(record)
		if err := publishRecord(p.root, ownershipFile(record.User), body); err != nil {
			return err
		}
		if record.User == TerraBaseUser {
			p.engineOwnership = &record
		} else {
			p.ownership = &record
		}
	}
	for _, entry := range p.seed.Entries {
		if ctx.Err() != nil {
			return ErrPublish
		}
		ready, err := p.ready(entry)
		if err != nil {
			return err
		}
		if !ready {
			return ErrPublish
		}
	}
	return nil
}

func (p *publication) openCredential(parent int, leaf string, entry Entry) (*os.File, error) {
	fd, err := unix.Openat(parent, leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "hostsecrets-credential")
	if safeFile(fd, p.uid, true) {
		return file, nil
	}
	if owner := p.entryOwnership(entry); owner != nil && safeFile(fd, owner.UID, true) {
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) == nil && stat.Gid == uint32(owner.GID) {
			return file, nil
		}
	}
	file.Close()
	return nil, ErrOwnership
}
func (p *publication) finishOwnership(file *os.File, entry Entry) error {
	record := p.entryOwnership(entry)
	if record == nil {
		return ErrOwnership
	}
	if err := file.Chown(record.UID, record.GID); err != nil {
		return ErrOwnership
	}
	if err := file.Chmod(0600); err != nil {
		return ErrOwnership
	}
	if err := file.Sync(); err != nil {
		return ErrPublish
	}
	// Traversal only: root keeps write control over configuration directories.
	// Credentials remain readable solely by their exact service UID.
	root, err := unix.Dup(p.root)
	if err != nil {
		return ErrOwnership
	}
	defer unix.Close(root)
	if unix.Fchmod(root, 0711) != nil || unix.Fsync(root) != nil {
		return ErrPublish
	}
	fd := root
	parts := strings.Split(entryName(entry), "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := childDirectory(fd, part, p.uid, false)
		if fd != root {
			unix.Close(fd)
		}
		if err != nil {
			return ErrOwnership
		}
		fd = next
		if unix.Fchmod(fd, 0711) != nil || unix.Fsync(fd) != nil {
			unix.Close(fd)
			return ErrPublish
		}
	}
	if fd != root {
		unix.Close(fd)
	}
	return nil
}
