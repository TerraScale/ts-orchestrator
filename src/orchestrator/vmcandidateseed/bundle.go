package vmcandidateseed

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// PersistBundle preserves original signed grant bytes on retries, including
// random ECDSA signatures whose hashes are part of subsequent transfer scopes.
func PersistBundle(directory, planSHA256 string, bundle []byte) ([]byte, error) {
	const name = "public-plan.json"
	dir, err := privateDirectory(directory, false)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dir)
	document := struct {
		PlanSHA256 string          `json:"planSha256"`
		Bundle     json.RawMessage `json:"bundle"`
	}{planSHA256, bundle}
	raw, err := json.Marshal(document)
	if err != nil || len(raw) > 2<<20 {
		return nil, invalidStore
	}
	if err := installArtifact(dir, name, raw); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, err
	}
	fd, err := unix.Openat(dir, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, invalidStore
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&07777 != 0600 || st.Uid != uint32(os.Geteuid()) || st.Nlink != 1 || st.Size < 1 || st.Size > 2<<20 {
		return nil, invalidStore
	}
	existing, err := io.ReadAll(io.LimitReader(f, 2<<20+1))
	if err != nil || int64(len(existing)) != st.Size {
		return nil, invalidStore
	}
	if json.Unmarshal(existing, &document) != nil || document.PlanSHA256 != planSHA256 {
		return nil, invalidStore
	}
	canonical, _ := json.Marshal(document)
	if !bytes.Equal(canonical, existing) {
		return nil, invalidStore
	}
	// Validate all original signatures and exact private-material pins before
	// returning an existing bundle instead of the newly generated signatures.
	var nodes struct {
		Candidates []struct {
			NodeID string `json:"nodeId"`
		} `json:"candidates"`
	}
	if json.Unmarshal(document.Bundle, &nodes) != nil || len(nodes.Candidates) != 2 {
		return nil, invalidStore
	}
	for _, node := range nodes.Candidates {
		m, err := Load(directory, node.NodeID, document.Bundle)
		if err != nil {
			return nil, err
		}
		match := m.PlanSHA256 == planSHA256
		m.Clear()
		if !match {
			return nil, invalidStore
		}
	}
	return append([]byte(nil), document.Bundle...), nil
}
