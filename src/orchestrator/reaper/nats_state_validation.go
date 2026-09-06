package reaper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const maximumReaperEntries = 128

var reaperErrorType = regexp.MustCompile(`^\*?[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)?$`)

func reaperBoundedText(value string, limit int) bool {
	if len(value) > limit || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
func reaperCycleName(entry Entry, base string) string {
	if entry.Cycle == 0 {
		return base
	}
	return fmt.Sprintf("%s/cycle-%d", base, entry.Cycle)
}
func reaperOperationName(entry Entry, name string) bool {
	if !reaperBoundedText(name, 600) {
		return false
	}
	base := name
	if before, suffix, found := strings.CutLast(base, "/cycle-"); found {
		cycle, err := strconv.ParseUint(suffix, 10, 64)
		if err != nil || cycle == 0 || cycle > entry.Cycle || strconv.FormatUint(cycle, 10) != suffix {
			return false
		}
		base = before
	}
	switch base {
	case "pause/snapshot", "pause/close", "pause/native-backup", "notice/pause/" + entry.DatabaseID, "notice/second/" + entry.DatabaseID, "notice/final/" + entry.DatabaseID:
		return true
	case "delete/cdn-purge", "delete/crypto-shred", "delete/data":
		return true
	}
	prefix := "reactivate/" + entry.DatabaseID + "/"
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	value := strings.TrimPrefix(name, prefix)
	_, err := strconv.ParseInt(value, 10, 64)
	return err == nil && base == name
}
func reaperAuditName(entry Entry, name string) bool {
	if !reaperBoundedText(name, 620) {
		return false
	}
	switch name {
	case "eligibility/" + entry.DatabaseID + "/paid", "eligibility/" + entry.DatabaseID + "/exempt", "eligibility/" + entry.DatabaseID + "/unknown-request", "eligibility/" + entry.DatabaseID + "/active", "delete/complete/" + entry.DatabaseID, "delete/request-after-fence/" + entry.DatabaseID:
		return true
	}
	if _, ok := entry.Operations[name]; ok {
		return true
	}
	for _, suffix := range []string{"/completed/" + entry.DatabaseID, "/failed/" + entry.DatabaseID} {
		if strings.HasSuffix(name, suffix) {
			_, ok := entry.Operations[strings.TrimSuffix(name, suffix)]
			return ok
		}
	}
	return false
}
func reaperDone(entry Entry, name string) bool { return entry.Operations[name].Status == operationDone }
func reaperStateBytes(state *State) ([]byte, error) {
	if state == nil {
		return nil, nil
	}
	if state.Version == 0 || len(state.Entries) > maximumReaperEntries || !reaperBoundedText(state.Cursor, 1024) {
		return nil, ErrStateUnavailable
	}
	for id, entry := range state.Entries {
		if !validDatabaseID(id) || !utf8.ValidString(id) || entry.DatabaseID != id || entry.Plan != PlanFree && entry.Plan != PlanPaid || len(entry.Operations) > 128 || len(entry.Audits) > 256 {
			return nil, ErrStateUnavailable
		}
		for name, op := range entry.Operations {
			if !reaperOperationName(entry, name) || op.Attempts == 0 || op.StartedAt.IsZero() || len(op.LastError) > 160 || op.LastError != "" && !reaperErrorType.MatchString(op.LastError) {
				return nil, ErrStateUnavailable
			}
			switch op.Status {
			case operationStarted:
				if !op.CompletedAt.IsZero() || op.LastError != "" {
					return nil, ErrStateUnavailable
				}
			case operationFailed:
				if !op.CompletedAt.IsZero() || op.LastError == "" {
					return nil, ErrStateUnavailable
				}
			case operationDone:
				if op.CompletedAt.IsZero() || op.CompletedAt.Before(op.StartedAt) || op.LastError != "" {
					return nil, ErrStateUnavailable
				}
			default:
				return nil, ErrStateUnavailable
			}
		}
		for name, done := range entry.Audits {
			if !done || !reaperAuditName(entry, name) {
				return nil, ErrStateUnavailable
			}
		}
		switch entry.Phase {
		case PhaseActive:
			if !entry.PausedAt.IsZero() || !entry.FirstNoticeAt.IsZero() || !entry.SecondNoticeAt.IsZero() || !entry.DeletedAt.IsZero() {
				return nil, ErrStateUnavailable
			}
		case PhasePaused, PhaseDeleting, PhaseDeleted:
			if entry.PausedAt.IsZero() {
				return nil, ErrStateUnavailable
			}
			for _, base := range []string{"pause/snapshot", "pause/close", "pause/native-backup"} {
				if !reaperDone(entry, reaperCycleName(entry, base)) {
					return nil, ErrStateUnavailable
				}
			}
			if entry.Phase != PhaseDeleted && !entry.DeletedAt.IsZero() {
				return nil, ErrStateUnavailable
			}
			if entry.Phase == PhaseDeleting || entry.Phase == PhaseDeleted {
				if entry.FirstNoticeAt.IsZero() {
					return nil, ErrStateUnavailable
				}
			}
			if entry.Phase == PhaseDeleted {
				if entry.DeletedAt.IsZero() || entry.SecondNoticeAt.IsZero() {
					return nil, ErrStateUnavailable
				}
				for _, name := range []string{"delete/cdn-purge", "delete/crypto-shred", "delete/data"} {
					if !reaperDone(entry, name) {
						return nil, ErrStateUnavailable
					}
				}
			}
		default:
			return nil, ErrStateUnavailable
		}
		for _, notice := range []struct {
			at   time.Time
			name string
		}{{entry.FirstNoticeAt, "notice/second/" + id}, {entry.SecondNoticeAt, "notice/final/" + id}} {
			if !notice.at.IsZero() && (notice.at.Before(entry.PausedAt) || !reaperDone(entry, reaperCycleName(entry, notice.name))) {
				return nil, ErrStateUnavailable
			}
		}
	}
	encoded, err := json.Marshal(state)
	if err != nil || len(encoded) > maximumReaperStateBytes {
		return nil, ErrStateUnavailable
	}
	return encoded, nil
}
func reaperIntentTransition(before, after *State) error {
	next, err := reaperStateBytes(after)
	if err != nil || after == nil {
		return ErrStateUnavailable
	}
	if before == nil {
		for _, entry := range after.Entries {
			if entry.Phase != PhaseActive || entry.Cycle != 0 || !reaperNewOperations(Entry{}, entry) {
				return ErrStateConflict
			}
		}
		return nil
	}
	previous, err := reaperStateBytes(before)
	if err != nil {
		return err
	}
	if bytes.Equal(previous, next) {
		return nil
	}
	if after.Version <= before.Version {
		return ErrStateConflict
	}
	for id, old := range before.Entries {
		entry, exists := after.Entries[id]
		if !exists || entry.LastRequest.Before(old.LastRequest) {
			return ErrStateConflict
		}
		reactivate := old.Phase == PhasePaused && entry.Phase == PhaseActive
		if reactivate {
			key := fmt.Sprintf("reactivate/%s/%d", id, entry.LastRequest.UnixNano())
			if old.Cycle == ^uint64(0) || entry.Cycle != old.Cycle+1 || !reaperDone(old, key) || !entry.LastRequest.After(old.PausedAt) {
				return ErrStateConflict
			}
		} else {
			if entry.Cycle != old.Cycle {
				return ErrStateConflict
			}
			if entry.Phase != old.Phase && !(old.Phase == PhaseActive && entry.Phase == PhasePaused || old.Phase == PhasePaused && entry.Phase == PhaseDeleting || old.Phase == PhaseDeleting && entry.Phase == PhaseDeleted) {
				return ErrStateConflict
			}
			for _, pair := range [][2]time.Time{{old.PausedAt, entry.PausedAt}, {old.FirstNoticeAt, entry.FirstNoticeAt}, {old.SecondNoticeAt, entry.SecondNoticeAt}, {old.DeletedAt, entry.DeletedAt}} {
				if !pair[0].IsZero() && !pair[1].Equal(pair[0]) {
					return ErrStateConflict
				}
			}
		}
		if !reaperNewOperations(old, entry) {
			return ErrStateConflict
		}
		for name, op := range old.Operations {
			updated, exists := entry.Operations[name]
			if !exists {
				return ErrStateConflict
			}
			if reflect.DeepEqual(op, updated) {
				continue
			}
			if op.Status == operationDone || updated.StartedAt.Before(op.StartedAt) {
				return ErrStateConflict
			}
			if updated.Status == operationStarted {
				if op.Attempts == ^uint32(0) || updated.Attempts != op.Attempts+1 {
					return ErrStateConflict
				}
			} else if op.Status != operationStarted || updated.Attempts != op.Attempts || !updated.StartedAt.Equal(op.StartedAt) {
				return ErrStateConflict
			}
		}
		for name, done := range old.Audits {
			if done && !entry.Audits[name] {
				return ErrStateConflict
			}
		}
	}
	for id, entry := range after.Entries {
		if _, exists := before.Entries[id]; !exists && (entry.Phase != PhaseActive || entry.Cycle != 0 || !reaperNewOperations(Entry{}, entry)) {
			return ErrStateConflict
		}
	}
	return nil
}

// A side effect must have a committed intent before any completion receipt.
func reaperNewOperations(old, entry Entry) bool {
	for name, op := range entry.Operations {
		if _, exists := old.Operations[name]; exists {
			continue
		}
		if op.Status != operationStarted || op.Attempts != 1 {
			return false
		}
		phase := old.Phase
		if phase == "" {
			phase = PhaseActive
		}
		switch name {
		case reaperCycleName(entry, "pause/snapshot"):
			if phase != PhaseActive {
				return false
			}
		case reaperCycleName(entry, "pause/close"):
			if phase != PhaseActive || !reaperDone(old, reaperCycleName(entry, "pause/snapshot")) {
				return false
			}
		case reaperCycleName(entry, "pause/native-backup"):
			if phase != PhaseActive || !reaperDone(old, reaperCycleName(entry, "pause/close")) {
				return false
			}
		case reaperCycleName(entry, "notice/pause/"+entry.DatabaseID):
			if phase != PhasePaused {
				return false
			}
		case reaperCycleName(entry, "notice/second/"+entry.DatabaseID):
			if phase != PhasePaused || !reaperDone(old, reaperCycleName(entry, "notice/pause/"+entry.DatabaseID)) {
				return false
			}
		case reaperCycleName(entry, "notice/final/"+entry.DatabaseID):
			if old.FirstNoticeAt.IsZero() || phase != PhasePaused && phase != PhaseDeleting {
				return false
			}
		case "delete/cdn-purge", "delete/crypto-shred", "delete/data":
			if phase != PhaseDeleting || old.SecondNoticeAt.IsZero() {
				return false
			}
			if name == "delete/crypto-shred" && !reaperDone(old, "delete/cdn-purge") || name == "delete/data" && !reaperDone(old, "delete/crypto-shred") {
				return false
			}
		default:
			if !strings.HasPrefix(name, "reactivate/"+entry.DatabaseID+"/") || phase != PhasePaused {
				return false
			}
		}
	}
	return true
}
