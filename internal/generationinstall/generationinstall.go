// Package generationinstall carries a root-signed material generation chain
// (TS-668) from an operator onto every controller's disk, one armed slot at
// a time. The authority leader keeps the cell's record in the root chain's
// bucket; each controller's Stager stages what its slot holds; selfupdate
// prepare installs an armed stage (bootstrapstart.InstallGeneration). Until
// an operator publishes a chain, nothing happens.
package generationinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"slices"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

const (
	// RecordKey is the cell's record in TS_TRUST_ROOTS.
	RecordKey    = "material-generations"
	statusPrefix = "material-generations.status."
	// MaxRecordBytes is the bucket's value limit. The record holds the chain
	// (at most 64 KiB per generation) and each slot's config (16 KiB).
	MaxRecordBytes       = trust.MaxRootChainBytes
	maxStatusBytes       = 4 << 10
	defaultStageInterval = 30 * time.Second
)

// Record is the published chain, each slot's config the newest generation
// pins, and the slots armed to install it. A new chain clears both.
type Record struct {
	Chain   []byte            `json:"chain"`
	Configs map[string][]byte `json:"configs,omitempty"`
	Armed   []string          `json:"armed,omitempty"`
}

// Status is one controller's report of its slot, by generation number.
type Status struct {
	Slot      string `json:"slot"`
	Staged    uint64 `json:"staged,omitzero"`
	Armed     bool   `json:"armed,omitzero"`
	Installed uint64 `json:"installed,omitzero"`
	Error     string `json:"error,omitempty"`
}

// Report is the record and every slot's status.
type Report struct {
	Generation  uint64   `json:"generation,omitzero"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Configs     []string `json:"configs,omitempty"`
	Armed       []string `json:"armed,omitempty"`
	Slots       []Status `json:"slots,omitempty"`
	// Status is the outcome of a change.
	Status string `json:"status,omitempty"`
}

// Leader changes the record on the authority leader. Every write is a CAS
// on the read revision, fenced by Guard to the leader's term. A chain only
// extends the stored one; stagers and prepare check that again, so a record
// written past the leader installs nothing either.
type Leader struct {
	KV       jetstream.KeyValue
	Expected bootstrap.MaterialGenerationExpectation
	Roots    func() trust.Keyring
	Guard    func(context.Context) error
	Now      func() time.Time
}

// Publish stores a chain that is root-signed for this cell under the
// current roots and strictly extends the stored one.
func (l Leader) Publish(ctx context.Context, wire []byte) (string, error) {
	chain, err := bootstrap.DecodeMaterialGenerationChain(wire)
	if err != nil {
		return "", err
	}
	if _, err := bootstrap.VerifyMaterialGenerationChain(chain, l.Roots(), l.Expected, now(l.Now)); err != nil {
		return "", err
	}
	return l.update(ctx, func(record *Record) (string, error) {
		if bytes.Equal(record.Chain, wire) {
			return "unchanged", nil
		}
		if stored, err := bootstrap.DecodeMaterialGenerationChain(record.Chain); err == nil &&
			!bootstrap.ExtendsMaterialGenerationChain(chain, stored) {
			return "", errors.New("the chain does not extend the published one: it replays or forks it")
		}
		*record = Record{Chain: wire}
		return "published", nil
	})
}

// SetConfig stores slot's config when it matches the newest generation's pin.
func (l Leader) SetConfig(ctx context.Context, slot string, config []byte) (string, error) {
	return l.update(ctx, func(record *Record) (string, error) {
		pin, err := configPin(record.Chain, slot)
		if err != nil {
			return "", err
		}
		if int64(len(config)) != pin.Size || digest(config) != pin.SHA256 {
			return "", fmt.Errorf("%s's config differs from the newest generation's pin", slot)
		}
		if bytes.Equal(record.Configs[slot], config) {
			return "unchanged", nil
		}
		if record.Configs == nil {
			record.Configs = map[string][]byte{}
		}
		record.Configs[slot] = config
		return "stored", nil
	})
}

// Arm adds slot to the armed slots, or removes it. A slot whose config the
// newest generation pins arms only once the config is stored.
func (l Leader) Arm(ctx context.Context, slot string, armed bool) (string, error) {
	if !slices.Contains(l.Expected.ControllerSlots, slot) {
		return "", fmt.Errorf("%q is not a controller slot of this cell", slot)
	}
	return l.update(ctx, func(record *Record) (string, error) {
		if len(record.Chain) == 0 {
			return "", errors.New("no material generation is published")
		}
		if slices.Contains(record.Armed, slot) == armed {
			return "unchanged", nil
		}
		if !armed {
			record.Armed = slices.DeleteFunc(record.Armed, func(held string) bool { return held == slot })
			return "disarmed", nil
		}
		if _, err := configPin(record.Chain, slot); err == nil && record.Configs[slot] == nil {
			return "", fmt.Errorf("store %s's config before arming it", slot)
		}
		record.Armed = append(record.Armed, slot)
		slices.Sort(record.Armed)
		return "armed", nil
	})
}

// update applies change to the stored record and writes it back with CAS.
// A record that does not decode reads as empty, so a chain can replace it.
func (l Leader) update(ctx context.Context, change func(*Record) (string, error)) (string, error) {
	var record Record
	revision := uint64(0)
	entry, err := l.KV.Get(ctx, RecordKey)
	switch {
	case err == nil:
		revision = entry.Revision()
		if protocol.DecodeTolerant(entry.Value(), &record, MaxRecordBytes) != nil {
			record = Record{}
		}
	case !errors.Is(err, jetstream.ErrKeyNotFound):
		return "", fmt.Errorf("read material generations: %w", err)
	}
	status, err := change(&record)
	if err != nil || status == "unchanged" {
		return status, err
	}
	value, err := protocol.EncodeJSON(record)
	if err != nil {
		return "", err
	}
	if len(value) > MaxRecordBytes {
		return "", fmt.Errorf("the material generation record would exceed %d bytes", MaxRecordBytes)
	}
	if err := l.Guard(ctx); err != nil {
		return "", err
	}
	if revision == 0 {
		_, err = l.KV.Create(ctx, RecordKey, value)
	} else {
		_, err = l.KV.Update(ctx, RecordKey, value, revision)
	}
	if err != nil {
		return "", fmt.Errorf("store material generations: %w", err)
	}
	return status, nil
}

// Report reads the record and every slot's status.
func (l Leader) Report(ctx context.Context) (Report, error) {
	var report Report
	entry, err := l.KV.Get(ctx, RecordKey)
	if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return Report{}, fmt.Errorf("read material generations: %w", err)
	}
	if err == nil {
		var record Record
		if err := protocol.DecodeTolerant(entry.Value(), &record, MaxRecordBytes); err != nil {
			return Report{}, fmt.Errorf("stored material generations: %w", err)
		}
		chain, err := bootstrap.DecodeMaterialGenerationChain(record.Chain)
		if err != nil {
			return Report{}, err
		}
		report.Generation = uint64(len(chain))
		if report.Fingerprint, err = trust.Fingerprint(chain[len(chain)-1]); err != nil {
			return Report{}, err
		}
		for slot := range record.Configs {
			report.Configs = append(report.Configs, slot)
		}
		slices.Sort(report.Configs)
		report.Armed = record.Armed
	}
	for _, slot := range l.Expected.ControllerSlots {
		status := Status{Slot: slot, Error: "no report"}
		if entry, err := l.KV.Get(ctx, statusPrefix+slot); err == nil {
			status = Status{}
			if protocol.DecodeTolerant(entry.Value(), &status, maxStatusBytes) != nil || status.Slot != slot {
				status = Status{Slot: slot, Error: "unreadable report"}
			}
		}
		report.Slots = append(report.Slots, status)
	}
	return report, nil
}

func configPin(chainWire []byte, slot string) (bootstrap.GenerationControllerConfig, error) {
	chain, err := bootstrap.DecodeMaterialGenerationChain(chainWire)
	if err != nil {
		return bootstrap.GenerationControllerConfig{}, errors.New("no material generation is published")
	}
	generation, err := bootstrap.MaterialGenerationPayload(chain[len(chain)-1])
	if err != nil {
		return bootstrap.GenerationControllerConfig{}, err
	}
	for _, pin := range generation.ControllerConfigs {
		if pin.Slot == slot {
			return pin, nil
		}
	}
	return bootstrap.GenerationControllerConfig{}, fmt.Errorf("the newest generation pins no config for %q", slot)
}

// Stager runs in every controller, unprivileged. It stages the published
// chain when it extends the installed one: the files its slot may hold (the
// unbound ones and its own, never another slot's) from Vault, its config,
// and the chain last, all checked by CheckGenerationFiles. While the record
// arms the slot it writes the armed marker prepare installs from.
type Stager struct {
	KV     jetstream.KeyValue
	Target bootstrapstart.GenerationTarget
	Roots  func() trust.Keyring
	// Read returns one secret's exact pinned bytes from Vault.
	Read func(context.Context, bootstrap.SecretReference) ([]byte, error)
	// Installed is the credential directory's adopted chain.
	Installed string
	Spool     string
	// RequireMemory refuses a spool off tmpfs with swap disabled: the staged
	// files are secrets (TS-745). Nil only in tests.
	RequireMemory func(string) error
	Interval      time.Duration
	Now           func() time.Time

	reported []byte
}

// Run stages and reports until ctx ends.
func (s *Stager) Run(ctx context.Context) {
	interval := s.Interval
	if interval <= 0 {
		interval = defaultStageInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		status := s.Pass(ctx)
		if err := s.report(ctx, status); err != nil && ctx.Err() == nil {
			slog.Warn("report material generation status", "component", "trust", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Pass stages once and returns the slot's status. Any failure leaves the
// slot disarmed.
func (s *Stager) Pass(ctx context.Context) Status {
	status := Status{Slot: s.Target.Slot}
	if err := os.MkdirAll(s.Spool, 0o700); err != nil {
		status.Error = err.Error()
		return status
	}
	if s.RequireMemory != nil {
		if err := s.RequireMemory(s.Spool); err != nil {
			status.Error = err.Error()
			return status
		}
	}
	spool, err := os.OpenRoot(s.Spool)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	defer spool.Close()
	if err := s.stage(ctx, spool, &status); err != nil {
		status.Error, status.Armed = err.Error(), false
		if err := spool.Remove(bootstrapstart.GenerationArmedFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			status.Error += "; " + err.Error()
		}
	}
	return status
}

func (s *Stager) stage(ctx context.Context, spool *os.Root, status *Status) error {
	installedWire, err := os.ReadFile(s.Installed)
	var installed []trust.Envelope
	if err == nil {
		installed, err = bootstrap.DecodeMaterialGenerationChain(installedWire)
	} else if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	if err != nil {
		return fmt.Errorf("read the installed generations: %w", err)
	}
	status.Installed = uint64(len(installed))
	entry, err := s.KV.Get(ctx, RecordKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return clearSpool(spool)
	}
	if err != nil {
		return err
	}
	var record Record
	if err := protocol.DecodeTolerant(entry.Value(), &record, MaxRecordBytes); err != nil {
		return fmt.Errorf("stored material generations: %w", err)
	}
	if bytes.Equal(record.Chain, installedWire) {
		return clearSpool(spool)
	}
	chain, err := bootstrap.DecodeMaterialGenerationChain(record.Chain)
	if err != nil {
		return err
	}
	verified, err := bootstrap.VerifyMaterialGenerationChain(chain, s.Roots(), s.Target.Expected, now(s.Now))
	if err != nil {
		return err
	}
	if !bootstrap.ExtendsMaterialGenerationChain(chain, installed) {
		return errors.New("the published chain does not extend the installed generations")
	}
	newest := verified[len(verified)-1]
	if staged, err := spool.ReadFile(bootstrapstart.MaterialGenerationsFile); err != nil || !bytes.Equal(staged, record.Chain) {
		if err := s.write(ctx, spool, newest.Generation(), record); err != nil {
			return errors.Join(err, clearSpool(spool))
		}
	}
	status.Staged = uint64(len(chain))
	if !slices.Contains(record.Armed, s.Target.Slot) {
		if err := spool.Remove(bootstrapstart.GenerationArmedFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	status.Armed = true
	return writeSpooled(spool, bootstrapstart.GenerationArmedFile, []byte(newest.Fingerprint()))
}

// write replaces the spool with the slot's stage, the chain last.
func (s *Stager) write(ctx context.Context, spool *os.Root, generation bootstrap.MaterialGeneration, record Record) error {
	if err := clearSpool(spool); err != nil {
		return err
	}
	slot := s.Target.Slot
	files := map[string][]byte{}
	for _, pin := range generation.ControllerConfigs {
		if pin.Slot != slot {
			continue
		}
		if pin.ManifestSHA256 != s.Target.ManifestSHA256 {
			return errors.New("the newest generation's config is for another manifest of this slot")
		}
		if record.Configs[slot] == nil {
			return errors.New("this slot's config is not stored yet")
		}
		files[bootstrapstart.GenerationConfigFile(slot)] = record.Configs[slot]
	}
	for _, secret := range generation.Secrets {
		if secret.Slot != "" && secret.Slot != slot {
			continue
		}
		data, err := s.Read(ctx, secret)
		if err != nil {
			return fmt.Errorf("read %s from Vault: %w", secret.TargetFile, err)
		}
		files[secret.TargetFile] = data
	}
	defer func() {
		for _, data := range files {
			clear(data)
		}
	}()
	if _, err := bootstrapmaterial.CheckGenerationFiles(generation, func(name string) ([]byte, error) {
		if data, ok := files[name]; ok {
			return data, nil
		}
		return nil, fs.ErrNotExist
	}, now(s.Now)); err != nil {
		return err
	}
	for name, data := range files {
		if err := writeSpooled(spool, name, data); err != nil {
			return err
		}
	}
	return writeSpooled(spool, bootstrapstart.MaterialGenerationsFile, record.Chain)
}

// report posts status to the slot's key when it changed.
func (s *Stager) report(ctx context.Context, status Status) error {
	value, err := protocol.EncodeJSON(status)
	if err != nil || bytes.Equal(value, s.reported) {
		return err
	}
	if _, err := s.KV.Put(ctx, statusPrefix+status.Slot, value); err != nil {
		return err
	}
	s.reported = value
	return nil
}

// writeSpooled replaces name beneath the spool through a synced temporary
// file, owner-only.
func writeSpooled(spool *os.Root, name string, data []byte) error {
	temporary := "." + name + ".tmp"
	file, err := spool.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Chmod(0o600)
	}
	if err == nil {
		err = file.Sync()
	}
	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}
	return spool.Rename(temporary, name)
}

// clearSpool removes the stage, the armed marker and the chain first.
func clearSpool(spool *os.Root) error {
	for _, name := range []string{bootstrapstart.GenerationArmedFile, bootstrapstart.MaterialGenerationsFile} {
		if err := spool.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	entries, err := fs.ReadDir(spool.FS(), ".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := spool.RemoveAll(entry.Name()); err != nil {
			return err
		}
	}
	return nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func now(clock func() time.Time) time.Time {
	if clock != nil {
		return clock()
	}
	return time.Now()
}
