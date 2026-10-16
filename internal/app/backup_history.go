package app

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
)

const backupHistoryCursorDomain = "TB-BACKUP-HISTORY-CURSOR-V1\x00"

type backupHistoryCursor struct {
	Version             uint64 `json:"version"`
	Actor               string `json:"actor"`
	Cell                string `json:"cell"`
	Stream              string `json:"stream"`
	DatabaseID          string `json:"database_id"`
	PartitionID         string `json:"partition_id"`
	OperationID         string `json:"operation_id"`
	Watermark           uint64 `json:"watermark"`
	NextSequence        uint64 `json:"next_sequence"`
	LatestMatchSequence uint64 `json:"latest_match_sequence"`
	IssuedAtMS          int64  `json:"issued_at_ms"`
	ExpiresAtMS         int64  `json:"expires_at_ms"`
}

type backupHistoryCursorEnvelope struct {
	Version   uint64 `json:"version"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func signBackupHistoryCursor(cursor backupHistoryCursor, key ed25519.PrivateKey) (string, error) {
	if len(key) != ed25519.PrivateKeySize || cursor.Watermark == 0 ||
		cursor.NextSequence == 0 || cursor.NextSequence > cursor.Watermark+1 {
		return "", errors.New("backup history cursor is invalid")
	}
	issued := time.Now().UTC()
	cursor.Version = 1
	cursor.IssuedAtMS = issued.UnixMilli()
	cursor.ExpiresAtMS = issued.Add(15 * time.Minute).UnixMilli()
	body, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(key, append([]byte(backupHistoryCursorDomain), body...))
	outer, err := json.Marshal(backupHistoryCursorEnvelope{Version: 1,
		Payload:   base64.RawURLEncoding.EncodeToString(body),
		Signature: base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil || len(outer) > 6<<10 {
		return "", errors.New("backup history cursor exceeds bound")
	}
	return base64.RawURLEncoding.EncodeToString(outer), nil
}

func verifyBackupHistoryCursor(token string, key ed25519.PublicKey, now time.Time,
	actor, cell, databaseID, partitionID, operationID string,
) (backupHistoryCursor, error) {
	if len(token) == 0 || len(token) > 8<<10 || len(key) != ed25519.PublicKeySize {
		return backupHistoryCursor{}, errors.New("history_cursor_expired")
	}
	outerBytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || base64.RawURLEncoding.EncodeToString(outerBytes) != token || len(outerBytes) > 6<<10 {
		return backupHistoryCursor{}, errors.New("history_cursor_expired")
	}
	var outer backupHistoryCursorEnvelope
	if err := json.Unmarshal(outerBytes, &outer, json.RejectUnknownMembers(true)); err != nil || outer.Version != 1 {
		return backupHistoryCursor{}, errors.New("history_cursor_expired")
	}
	canonical, err := json.Marshal(outer)
	if err != nil || !bytes.Equal(canonical, outerBytes) {
		return backupHistoryCursor{}, errors.New("history_cursor_expired")
	}
	body, err := base64.RawURLEncoding.DecodeString(outer.Payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(body) != outer.Payload {
		return backupHistoryCursor{}, errors.New("history_cursor_expired")
	}
	signature, err := base64.RawURLEncoding.DecodeString(outer.Signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != outer.Signature ||
		!ed25519.Verify(key, append([]byte(backupHistoryCursorDomain), body...), signature) {
		return backupHistoryCursor{}, errors.New("history_cursor_expired")
	}
	var cursor backupHistoryCursor
	if err := json.Unmarshal(body, &cursor, json.RejectUnknownMembers(true)); err != nil {
		return backupHistoryCursor{}, errors.New("history_cursor_expired")
	}
	canonical, err = json.Marshal(cursor)
	if err != nil || !bytes.Equal(canonical, body) || cursor.Version != 1 ||
		cursor.Actor != actor || cursor.Cell != cell || cursor.Stream != authority.ControlStreamName ||
		cursor.DatabaseID != databaseID || cursor.PartitionID != partitionID ||
		cursor.OperationID != operationID || cursor.Watermark == 0 ||
		cursor.NextSequence == 0 || cursor.NextSequence > cursor.Watermark+1 ||
		cursor.LatestMatchSequence > cursor.Watermark ||
		cursor.IssuedAtMS <= 0 || cursor.ExpiresAtMS-cursor.IssuedAtMS != int64(15*time.Minute/time.Millisecond) ||
		now.UnixMilli() > cursor.ExpiresAtMS ||
		cursor.IssuedAtMS > now.Add(30*time.Second).UnixMilli() {
		return backupHistoryCursor{}, errors.New("history_cursor_expired")
	}
	return cursor, nil
}
