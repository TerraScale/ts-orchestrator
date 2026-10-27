package manager

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// The value is computed from the rendered file, never configured by an
// operator. A task change makes the combined server reload its static OIDC
// clients while retaining its existing data mount and identity.
const serverConfigDigest = "TS_ORCH_NETBIRD_CONFIG_SHA256"

func reconcileServerConfig(ctx context.Context, config []byte) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	wire, err := exec.CommandContext(ctx, self, "service", "inspect", "netbird-server").Output()
	if err != nil {
		return fmt.Errorf("inspect NetBird server config generation: %w", err)
	}
	spec, changed, err := serverConfigSpec(wire, config)
	if err != nil || !changed {
		return err
	}
	apply := exec.CommandContext(ctx, self, "service", "apply", "-f", "/dev/stdin")
	apply.Stdin = bytes.NewReader(spec)
	// Neither the rendered config nor subprocess output belongs in logs.
	if err := apply.Run(); err != nil {
		return fmt.Errorf("roll out NetBird server config generation: %w", err)
	}
	return nil
}

func serverConfigSpec(inspection, config []byte) ([]byte, bool, error) {
	var service struct {
		Spec map[string]jsontext.Value `json:"spec"`
	}
	if err := json.Unmarshal(inspection, &service); err != nil {
		return nil, false, errors.New("invalid NetBird server inspection")
	}
	var name string
	if json.Unmarshal(service.Spec["name"], &name) != nil || name != "netbird-server" {
		return nil, false, errors.New("NetBird config rollout requires the existing server service")
	}
	env := map[string]string{}
	if raw := service.Spec["env"]; len(raw) != 0 && string(raw) != "null" {
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, false, errors.New("invalid NetBird server environment")
		}
	}
	sum := sha256.Sum256(config)
	digest := hex.EncodeToString(sum[:])
	if env[serverConfigDigest] == digest {
		return nil, false, nil
	}
	env[serverConfigDigest] = digest
	service.Spec["env"], _ = json.Marshal(env)
	// Inspect returns the local declaration without mesh placement. The M1
	// manager and its durable store reside in GRU; do not replicate SQLite.
	service.Spec["regions"] = jsontext.Value(`["gru"]`)
	wire, err := json.Marshal(service.Spec)
	return wire, true, err
}

func serverBinaryChanged() (bool, error) {
	installed, err := os.Executable()
	if err != nil {
		return false, err
	}
	return differentBinary("/proc/self/exe", installed)
}

func differentBinary(running, installed string) (bool, error) {
	before, err := os.Stat(running)
	if err != nil {
		return false, err
	}
	after, err := os.Stat(installed)
	if err != nil {
		return false, err
	}
	return !os.SameFile(before, after), nil
}
