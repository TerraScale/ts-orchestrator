package bootstrapstart

import (
	"io"
	"os"

	"golang.org/x/sys/unix"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapmaterial"
)

// MaterialGenerationsFile is the controller's adopted material generation
// chain (TS-568), kept in the credential directory beside the files it pins.
const MaterialGenerationsFile = "material-generations.json"

// MaterialPins is what restart admission expects in the credential directory.
// The complete accepted baseline is overlaid by the verified newest generation.
// Local issued files may retain their baseline bytes or satisfy that generation's
// issuance rules. Shared and nonrenewable baseline files remain pinned.
type MaterialPins struct {
	Digests map[string]string
	// Issued maps each issued file to its accepted baseline digest; empty before a
	// generation with controller issuers is adopted.
	Issued         map[string]string
	Generation     *bootstrap.VerifiedMaterialGeneration
	slot           string
	acceptance     string
	acceptedSHA256 string
	references     []bootstrap.SecretReference
	identity       bootstrapmaterial.LeafIdentity
	target         GenerationTarget
	// config is the loaded controller config, which a v1 generation
	// pins as controller-<slot>.json (TS-668).
	config []byte
}

// readUnpinned reads a service-owned credential file whose digest is not
// pinned, with readMaterial's ownership, mode, link and size checks.
func readUnpinned(dir int, name string, uid, gid uint32, maximum int64) ([]byte, error) {
	if !markerNameRE.MatchString(name) || maximum <= 0 {
		return nil, ErrMaterial
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != uid || stat.Gid != gid || stat.Mode&0o777 != 0o600 || stat.Nlink != 1 ||
		stat.Size <= 0 || stat.Size > maximum {
		return nil, ErrMaterial
	}
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(content) == 0 || int64(len(content)) > maximum {
		clear(content)
		return nil, ErrMaterial
	}
	return content, nil
}
