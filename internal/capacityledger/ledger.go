package capacityledger

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

const Version = 1
const maxHosts = 1024

type Receipt struct {
	OperationID         string    `json:"operationId"`
	RecipeSHA256        string    `json:"recipeSha256"`
	GrantSHA256         string    `json:"grantSha256"`
	GrantGeneration     uint64    `json:"grantGeneration"`
	LogicalScopeSHA256  string    `json:"logicalScopeSha256"`
	ResolvedScopeSHA256 string    `json:"resolvedScopeSha256"`
	BindingSHA256       string    `json:"bindingSha256,omitempty"`
	TenancyID           string    `json:"tenancyId"`
	QuoteSHA256         string    `json:"quoteSha256"`
	ReservedAt          time.Time `json:"reservedAt"`
	Quote               Quote     `json:"quote"`
}

func (r Receipt) Validate() error {
	if !entityid.Valid(r.OperationID) || !Digest(r.RecipeSHA256) || !Digest(r.GrantSHA256) || r.GrantGeneration == 0 ||
		!Digest(r.LogicalScopeSHA256) || !Digest(r.ResolvedScopeSHA256) || r.ResolvedScopeSHA256 != r.Quote.ScopeSHA256 ||
		r.BindingSHA256 == "" && r.LogicalScopeSHA256 != r.ResolvedScopeSHA256 || r.BindingSHA256 != "" && !Digest(r.BindingSHA256) ||
		!strings.HasPrefix(r.TenancyID, "ocid1.tenancy.") || r.QuoteSHA256 != r.Quote.SHA256() || r.ReservedAt.Before(r.Quote.IssuedAt) || !r.ReservedAt.Before(r.Quote.ExpiresAt) {
		return errors.New("financial receipt differs from its original grant, quote, scope or operation")
	}
	return r.Quote.Validate()
}

// Host binds one original reservation to one positively identified birth.
// Replacement hosts must have another reservation and another operation ID.
type Host struct {
	Receipt           Receipt   `json:"receipt"`
	RequestSHA256     string    `json:"requestSha256,omitempty"`
	StartedAt         time.Time `json:"startedAt,omitzero"`
	BornAt            time.Time `json:"bornAt,omitzero"`
	InstanceID        string    `json:"instanceId,omitempty"`
	BootVolumeID      string    `json:"bootVolumeId,omitempty"`
	InstanceRetiredAt time.Time `json:"instanceRetiredAt,omitzero"`
	BootRetiredAt     time.Time `json:"bootRetiredAt,omitzero"`
}

type Ledger struct {
	Version int    `json:"version"`
	Hosts   []Host `json:"hosts,omitempty"`
}

func (l Ledger) Clone() Ledger {
	l.Hosts = slices.Clone(l.Hosts)
	for i := range l.Hosts {
		l.Hosts[i].Receipt.Quote = l.Hosts[i].Receipt.Quote.Clone()
	}
	return l
}

func (l Ledger) Validate() error {
	if l.Version != Version || len(l.Hosts) > maxHosts {
		return errors.New("protected capacity ledger has invalid version or exceeds retained history bound")
	}
	ops, resources := map[string]bool{}, map[string]bool{}
	for _, host := range l.Hosts {
		if err := host.Receipt.Validate(); err != nil {
			return err
		}
		if ops[host.Receipt.OperationID] {
			return errors.New("capacity ledger repeats an original reservation")
		}
		ops[host.Receipt.OperationID] = true
		if host.RequestSHA256 == "" {
			if !host.StartedAt.IsZero() || !host.BornAt.IsZero() || host.InstanceID != "" || host.BootVolumeID != "" {
				return errors.New("capacity host has effects without its original prepared request")
			}
		} else if !Digest(host.RequestSHA256) || host.StartedAt.Before(host.Receipt.ReservedAt) {
			return errors.New("capacity host request lacks original identity or first attempt")
		}
		if host.BornAt.IsZero() {
			if host.InstanceID != "" || host.BootVolumeID != "" || !host.InstanceRetiredAt.IsZero() || !host.BootRetiredAt.IsZero() {
				return errors.New("capacity host lacks a positive exact birth")
			}
			continue
		}
		if host.BornAt.Before(host.StartedAt) || !strings.HasPrefix(host.InstanceID, "ocid1.instance.") || !strings.HasPrefix(host.BootVolumeID, "ocid1.bootvolume.") ||
			resources[host.InstanceID] || resources[host.BootVolumeID] ||
			!host.InstanceRetiredAt.IsZero() && host.InstanceRetiredAt.Before(host.BornAt) || !host.BootRetiredAt.IsZero() && host.BootRetiredAt.Before(host.BornAt) {
			return errors.New("capacity birth or terminal evidence repeats, rebinds or predates its exact original resources")
		}
		resources[host.InstanceID], resources[host.BootVolumeID] = true, true
	}
	return nil
}

// Reserve freezes the home receipt before any launch can be prepared.
func (l *Ledger) Reserve(receipt Receipt) error {
	if l == nil {
		return errors.New("protected capacity ledger is absent")
	}
	if err := receipt.Validate(); err != nil {
		return err
	}
	if l.Version == 0 && len(l.Hosts) == 0 {
		l.Version = Version
	}
	if err := l.Validate(); err != nil {
		return err
	}
	if i := l.index(receipt.OperationID); i >= 0 {
		if !equal(l.Hosts[i].Receipt, receipt) {
			return errors.New("original reservation cannot change its tariff, grant, geometry or scope")
		}
		return nil
	}
	if len(l.Hosts) == maxHosts {
		return errors.New("capacity ledger is full; retained and unresolved commitments cannot be discarded")
	}
	receipt.Quote = receipt.Quote.Clone()
	l.Hosts = append(l.Hosts, Host{Receipt: receipt})
	return nil
}

func (l *Ledger) Prepare(operationID, requestSHA256 string, startedAt time.Time) error {
	return l.change(operationID, func(host *Host) error {
		if host.RequestSHA256 != "" {
			if host.RequestSHA256 != requestSHA256 || !host.StartedAt.Equal(startedAt) {
				return errors.New("prepared launch cannot replace its request or first attempt")
			}
			return nil
		}
		host.RequestSHA256, host.StartedAt = requestSHA256, startedAt
		return nil
	})
}

// BindBirth accepts only exact SDK-proven IDs, supplied by the protected handler.
func (l *Ledger) BindBirth(operationID, requestSHA256, instanceID, bootVolumeID string, bornAt time.Time) error {
	return l.change(operationID, func(host *Host) error {
		if host.RequestSHA256 == "" || host.RequestSHA256 != requestSHA256 {
			return errors.New("birth differs from the original prepared SDK request")
		}
		if !host.BornAt.IsZero() {
			if host.InstanceID != instanceID || host.BootVolumeID != bootVolumeID || !host.BornAt.Equal(bornAt) {
				return errors.New("original reservation is already bound to another exact birth")
			}
			return nil
		}
		host.InstanceID, host.BootVolumeID, host.BornAt = instanceID, bootVolumeID, bornAt
		return nil
	})
}

// RetireResource records positive terminal SDK evidence, never absence or a 404.
func (l *Ledger) RetireResource(operationID, resourceID string, observedAt time.Time) error {
	return l.change(operationID, func(host *Host) error {
		if host.BornAt.IsZero() || observedAt.Before(host.BornAt) {
			return errors.New("terminal resource has no exact prior birth")
		}
		switch resourceID {
		case host.InstanceID:
			if host.InstanceRetiredAt.IsZero() {
				host.InstanceRetiredAt = observedAt
			}
		case host.BootVolumeID:
			if host.BootRetiredAt.IsZero() {
				host.BootRetiredAt = observedAt
			}
		default:
			return errors.New("terminal resource differs from the original exact child and boot IDs")
		}
		return nil
	})
}

func (l *Ledger) change(operationID string, update func(*Host) error) error {
	if l == nil {
		return errors.New("protected capacity ledger is absent")
	}
	if err := l.Validate(); err != nil {
		return err
	}
	i := l.index(operationID)
	if i < 0 {
		return errors.New("capacity operation has no original financial reservation")
	}
	next := l.Clone()
	if err := update(&next.Hosts[i]); err != nil {
		return err
	}
	if err := next.Validate(); err != nil {
		return err
	}
	*l = next
	return nil
}

func (l Ledger) index(operationID string) int {
	return slices.IndexFunc(l.Hosts, func(host Host) bool { return host.Receipt.OperationID == operationID })
}

// Monthly retains a full original node-plus-boot ceiling whenever either
// resource existed this month. Unknown outcomes remain charged across rollover.
func (l Ledger) Monthly(now time.Time) (uint64, error) {
	if err := l.Validate(); err != nil {
		return 0, err
	}
	month := time.Date(now.UTC().Year(), now.UTC().Month(), 1, 0, 0, 0, 0, time.UTC)
	var total uint64
	for _, host := range l.Hosts {
		if host.Receipt.ReservedAt.After(now) || host.StartedAt.After(now) || host.BornAt.After(now) || host.InstanceRetiredAt.After(now) || host.BootRetiredAt.After(now) {
			return 0, errors.New("capacity liability contains future lifecycle evidence")
		}
		if !host.InstanceRetiredAt.IsZero() && host.InstanceRetiredAt.Before(month) && !host.BootRetiredAt.IsZero() && host.BootRetiredAt.Before(month) {
			continue
		}
		if ^uint64(0)-total < host.Receipt.Quote.MonthlyCents {
			return 0, fmt.Errorf("original capacity liabilities exceed the supported monthly range")
		}
		total += host.Receipt.Quote.MonthlyCents
	}
	return total, nil
}

func equal(a, b any) bool {
	left, leftErr := json.Marshal(a, json.Deterministic(true))
	right, rightErr := json.Marshal(b, json.Deterministic(true))
	return leftErr == nil && rightErr == nil && string(left) == string(right)
}
