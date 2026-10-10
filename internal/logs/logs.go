// Package logs classifies journal records into classes: service, level,
// component and a normalized message. The host agent counts them per minute
// and ts-orch log-scan counts them over a period, so both read a record alike.
package logs

import (
	"encoding/json"
	"strconv"
	"time"
)

// The levels, from least to most severe.
const (
	LevelDebug = "DEBUG"
	LevelInfo  = "INFO"
	LevelWarn  = "WARN"
	LevelError = "ERROR"
)

var levels = []string{LevelDebug, LevelInfo, LevelWarn, LevelError}

// Entry is one journal record from `journalctl --output=json`.
type Entry struct {
	Unit, Comm, PID, Message string
	// Priority is the journal's syslog PRIORITY; empty when absent.
	Priority string
	At       time.Time
}

// Record is one classified log record.
type Record struct {
	Service, Level, Component string
	// Message is the normalized message, the text of the record's class.
	Message string
	// Example is the raw message, at most 512 bytes.
	Example string
}

// DecodeJournal reads one line of journalctl's JSON. A record whose MESSAGE is
// not text, which journalctl prints as an array of bytes, is not a log line.
func DecodeJournal(line []byte) (Entry, bool) {
	var raw struct {
		Unit     string          `json:"_SYSTEMD_UNIT"`
		Comm     string          `json:"_COMM"`
		PID      string          `json:"_PID"`
		Priority string          `json:"PRIORITY"`
		Realtime string          `json:"__REALTIME_TIMESTAMP"`
		Message  json.RawMessage `json:"MESSAGE"`
	}
	if json.Unmarshal(line, &raw) != nil {
		return Entry{}, false
	}
	var message string
	if json.Unmarshal(raw.Message, &message) != nil {
		return Entry{}, false
	}
	entry := Entry{Unit: raw.Unit, Comm: raw.Comm, PID: raw.PID, Message: message, Priority: raw.Priority}
	if micros, err := strconv.ParseInt(raw.Realtime, 10, 64); err == nil {
		entry.At = time.UnixMicro(micros)
	}
	return entry, true
}

func validLevel(level string) bool {
	return severity(level) >= 0
}

func severity(level string) int {
	for i, known := range levels {
		if known == level {
			return i
		}
	}
	return -1
}
