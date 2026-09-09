package vmengineconfig

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
)

var backupFilePattern = regexp.MustCompile(`^/etc/terrascale/backup/[0-9A-HJKMNP-TV-Z]{26}-[0-9]+-(access|secret)$`)

func IsBackupPath(path string) bool { return backupFilePattern.MatchString(path) }
func backupPath(database string, index int, kind string) string {
	return fmt.Sprintf("/etc/terrascale/backup/%s-%d-%s", database, index, kind)
}
func (m *Material) BackupFiles() map[string][]byte {
	out := make(map[string][]byte, len(m.backupFiles))
	for path, data := range m.backupFiles {
		out[path] = bytes.Clone(data)
	}
	return out
}
func prepareBackup(m *Material, d Declaration) error {
	m.backupFiles = make(map[string][]byte)
	for _, db := range d.Databases {
		if db.Backup == nil {
			continue
		}
		for i, dest := range db.Backup.Destinations {
			if db.BYOK != nil && i == 0 {
				continue
			}
			for kind, path := range map[string]string{"access": dest.AccessKeyFile, "secret": dest.SecretKeyFile} {
				data, err := initialgrant.ReadMaterialFile(path, 16<<10, true)
				if err != nil || len(bytes.TrimSpace(data)) == 0 {
					clear(data)
					return errors.New("vmengineconfig: protected backup credential read refused")
				}
				m.backupFiles[backupPath(db.Database, i, kind)] = data
			}
		}
	}
	return nil
}
