package bootstrapmaterial

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/nats-io/nkeys"
)

// GenerateAdmissionCandidate is mechanical unpublished DATA generation. Only
// region's verified original-document Generate entry authenticates permission;
// neither this helper nor its result proves actor, escrow or source selection.
func GenerateAdmissionCandidate(directory string, cfg Config, authorization release.AdmissionAttestorAuthorization, now time.Time) (Record, error) {
	wireDigest, err := authorization.Digest()
	configWire, configErr := json.Marshal(cfg, json.Deterministic(true))
	if err != nil || wireDigest == "" || configErr != nil || authorization.PlanSHA256 != digest(configWire) || cfg.Validate() != nil || authorization.DeploymentID != cfg.DeploymentID || authorization.ClusterID != cfg.ClusterID || authorization.Environment != cfg.Environment || authorization.Cell != strings.ToUpper(cfg.Cell) {
		return Record{}, ErrMaterial
	}
	return generate(directory, cfg, now, &authorization)
}

func matchAdmissionAuthorization(record Record, authorization *release.AdmissionAttestorAuthorization) error {
	if authorization == nil {
		if record.Public.AdmissionAttestor != (release.AdmissionAttestorMaterial{}) {
			return ErrMaterial
		}
		return nil
	}
	want, err := authorization.Digest()
	if err != nil || record.Public.AdmissionAttestor.Validate() != nil || record.Public.AdmissionAttestor.AuthorizationSHA256 != want {
		return ErrMaterial
	}
	return nil
}

func buildAdmissionAttestor(files map[string][]byte, public *Public, authorization release.AdmissionAttestorAuthorization) error {
	authDigest, err := authorization.Digest()
	if err != nil {
		return ErrMaterial
	}
	key, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(private)
	public.AdmissionAttestor = release.AdmissionAttestorMaterial{AuthorizationSHA256: authDigest, PublicKey: base64.StdEncoding.EncodeToString(key)}
	if !dedicatedAdmissionKey(*public) {
		return ErrMaterial
	}
	wire := []byte(base64.StdEncoding.EncodeToString(private) + "\n")
	defer clear(wire)
	for _, slot := range authorization.ControllerSlots {
		files[slot+"-admission.key"] = bytes.Clone(wire)
	}
	return nil
}

func dedicatedAdmissionKey(public Public) bool {
	if public.AdmissionAttestor.Validate() != nil {
		return false
	}
	key, _ := base64.StdEncoding.Strict().DecodeString(public.AdmissionAttestor.PublicKey)
	for _, issuer := range []string{public.PeerSignerPublicKey, public.LedgerSignerPublicKey, public.TicketSignerPublicKey, public.ControllerResponsePublicKey} {
		decoded, err := base64.StdEncoding.Strict().DecodeString(issuer)
		if err != nil || len(decoded) != ed25519.PublicKeySize || bytes.Equal(key, decoded) {
			return false
		}
	}
	for _, issuer := range []struct {
		prefix nkeys.PrefixByte
		key    string
	}{{nkeys.PrefixByteOperator, public.OperatorNKey}, {nkeys.PrefixByteAccount, public.SystemAccountNKey}, {nkeys.PrefixByteAccount, public.CellAccountNKey}, {nkeys.PrefixByteAccount, public.HostNATSIssuerNKey}, {nkeys.PrefixByteAccount, public.ControllerAccountSignerNKey}} {
		decoded, err := nkeys.Decode(issuer.prefix, []byte(issuer.key))
		if err != nil || bytes.Equal(key, decoded) {
			return false
		}
	}
	return true
}

func validateAdmissionAttestor(directory string, record Record) error {
	present := record.Public.AdmissionAttestor != (release.AdmissionAttestorMaterial{})
	if present && ValidateAdmissionInventory(record) != nil {
		return ErrMaterial
	}
	count := 0
	seen := map[string]bool{}
	for _, file := range record.Files {
		if !strings.HasSuffix(file.Name, "-admission.key") {
			continue
		}
		count++
		if !present || seen[file.Slot] || !dedicatedAdmissionKey(record.Public) || file.Purpose != bootstrap.SecretController || !slices.Contains([]string{"controller-a", "controller-b", "controller-c"}, file.Slot) || file.Name != file.Slot+"-admission.key" {
			return ErrMaterial
		}
		seen[file.Slot] = true
		wire, err := readOwnedFile(filepath.Join(directory, file.Name), file.MaxBytes)
		if err != nil {
			return ErrMaterial
		}
		private, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSuffix(string(wire), "\n"))
		clear(wire)
		valid := err == nil && validEd25519Private(private)
		if valid {
			valid = base64.StdEncoding.EncodeToString(ed25519.PrivateKey(private).Public().(ed25519.PublicKey)) == record.Public.AdmissionAttestor.PublicKey
		}
		clear(private)
		if !valid {
			return ErrMaterial
		}
	}
	if count != 3*boolInt(present) {
		return ErrMaterial
	}
	return nil
}

// ValidateAdmissionInventory checks public DATA only, never source selection.
func ValidateAdmissionInventory(record Record) error {
	if !dedicatedAdmissionKey(record.Public) || record.Config.Validate() != nil || record.SchemaVersion != 1 {
		return ErrMaterial
	}
	seen := map[string]bool{}
	for _, file := range record.Files {
		if !strings.HasSuffix(file.Name, "-admission.key") {
			continue
		}
		hash, err := hex.DecodeString(file.SHA256)
		if seen[file.Slot] || !slices.Contains([]string{"controller-a", "controller-b", "controller-c"}, file.Slot) || file.Name != file.Slot+"-admission.key" || file.Purpose != bootstrap.SecretController || err != nil || len(hash) != 32 || file.SHA256 != strings.ToLower(file.SHA256) || file.MaxBytes != int64(base64.StdEncoding.EncodedLen(ed25519.PrivateKeySize)+1) {
			return ErrMaterial
		}
		seen[file.Slot] = true
	}
	if len(seen) != 3 {
		return ErrMaterial
	}
	return nil
}
