package releasepush

import "path/filepath"

type installedDigests struct {
	SHA256 []string `json:"sha256"`
}

func installedFile(trial string) string {
	return filepath.Join(filepath.Dir(trial), "release-installed")
}

func recordInstall(trial, binary, next string) error {
	current, err := binaryIdentity(binary)
	if err != nil {
		return err
	}
	incoming, err := binaryIdentity(next)
	if err != nil {
		return err
	}
	return writeJSON(installedFile(trial), installedDigests{SHA256: []string{current.SHA256, incoming.SHA256}})
}
