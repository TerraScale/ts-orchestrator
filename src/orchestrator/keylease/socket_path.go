package keylease

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Socket access has a dedicated traversal-only group. Catalog and credential
// paths use privateRoot instead and remain inaccessible to the engine identity.
func socketRoot(path string, gid uint32) (*os.Root, string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, "", ErrUnavailable
	}
	dir := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != dir {
		return nil, "", ErrUnavailable
	}
	for ancestor := dir; ; ancestor = filepath.Dir(ancestor) {
		var st unix.Stat_t
		if unix.Lstat(ancestor, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) {
			return nil, "", ErrUnavailable
		}
		if ancestor == dir && (st.Mode&0777 != 0710 || st.Uid != uint32(os.Geteuid()) || st.Gid != gid) {
			return nil, "", ErrUnavailable
		}
		if ancestor == "/" {
			break
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, "", ErrUnavailable
	}
	return root, filepath.Base(path), nil
}
