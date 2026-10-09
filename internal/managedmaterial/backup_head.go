package managedmaterial

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json/v2"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
)

// Rust's BackupCatalogHead::encode uses this framed canonical JSON. The
// controller checks only head identity and ancestry; catalog and closure
// qualification remains the owner's and each member's independent duty.
type backupCatalogHeadWire struct {
	BackupSet          [16]int           `json:"backup_set"`
	BackupTargetDigest [32]int           `json:"backup_target_digest"`
	Generation         uint64            `json:"generation"`
	EncryptionKeyID    string            `json:"encryption_key_id"`
	Catalog            backupBlobRefWire `json:"catalog"`
	PreviousHeadSHA256 [32]int           `json:"previous_head_sha256"`
}

type backupBlobRefWire struct {
	Key              string  `json:"key"`
	PointOrdinal     uint64  `json:"point_ordinal"`
	CiphertextLen    uint64  `json:"ciphertext_len"`
	CiphertextSHA256 [32]int `json:"ciphertext_sha256"`
	PlaintextLen     uint64  `json:"plaintext_len"`
	PlaintextSHA256  [32]int `json:"plaintext_sha256"`
	Nonce            [12]int `json:"nonce"`
}

func backupNumericArrayBytes(values []int) ([]byte, bool) {
	result := make([]byte, len(values))
	for index, value := range values {
		if value < 0 || value > 255 {
			return nil, false
		}
		result[index] = byte(value)
	}
	return result, true
}

func verifyBackupCatalogHeadBytes(headBytes []byte, record authority.BackupOperationRecord,
	previousHeadSHA string,
) bool {
	if len(headBytes) < 12 || len(headBytes) > 4096 ||
		!bytes.Equal(headBytes[:8], []byte("TBBKH001")) ||
		binary.LittleEndian.Uint32(headBytes[8:12]) != uint32(len(headBytes)-12) {
		return false
	}
	var head backupCatalogHeadWire
	body := headBytes[12:]
	if err := json.Unmarshal(body, &head, json.RejectUnknownMembers(true)); err != nil {
		return false
	}
	canonical, err := json.Marshal(head)
	if err != nil || !bytes.Equal(canonical, body) || head.Generation != record.Ordinal ||
		head.Catalog.PointOrdinal != record.Ordinal ||
		head.EncryptionKeyID == "" || len(head.EncryptionKeyID) > 256 ||
		head.Catalog.PlaintextLen == 0 || head.Catalog.PlaintextLen > 8<<20 ||
		head.Catalog.CiphertextLen != head.Catalog.PlaintextLen+16 ||
		!strings.HasPrefix(head.Catalog.Key, "tb-backups/v1/objects/") ||
		len(head.Catalog.Key) != len("tb-backups/v1/objects/")+32 {
		return false
	}
	for _, value := range head.EncryptionKeyID {
		if value < '!' || value > '~' {
			return false
		}
	}
	for _, value := range head.Catalog.Key[len("tb-backups/v1/objects/"):] {
		if value < '0' || value > '9' && (value < 'a' || value > 'f') {
			return false
		}
	}
	expectedSet, setErr := entityid.Parse(record.BackupSet)
	set, setOK := backupNumericArrayBytes(head.BackupSet[:])
	target, targetOK := backupNumericArrayBytes(head.BackupTargetDigest[:])
	previous, previousOK := backupNumericArrayBytes(head.PreviousHeadSHA256[:])
	cipherHash, cipherOK := backupNumericArrayBytes(head.Catalog.CiphertextSHA256[:])
	plainHash, plainOK := backupNumericArrayBytes(head.Catalog.PlaintextSHA256[:])
	_, nonceOK := backupNumericArrayBytes(head.Catalog.Nonce[:])
	if !setOK || !targetOK || !previousOK || !cipherOK || !plainOK || !nonceOK ||
		setErr != nil || !bytes.Equal(set, expectedSet[:]) ||
		hex.EncodeToString(target) != record.BackupTargetDigest ||
		hex.EncodeToString(previous) != previousHeadSHA ||
		bytes.Equal(cipherHash, make([]byte, 32)) || bytes.Equal(plainHash, make([]byte, 32)) {
		return false
	}
	return true
}
