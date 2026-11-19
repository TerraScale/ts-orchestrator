package releasepush

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ocirelease"
	"github.com/TerraScale/ts-orchestrator/internal/releaseattest"
)

type installedSeq struct {
	Seq    uint64 `json:"seq"`
	Tag    string `json:"tag"`
	SHA256 string `json:"sha256"`
}

func seqFile(state string) string { return filepath.Join(state, "nats", "release-seq.json") }

func channelSeqFile(state string) string { return filepath.Join(state, "nats", "release-channel-seq") }

func readSeq(path string) (installedSeq, error) {
	var record installedSeq
	present, err := readRecord(path, &record)
	if err != nil || !present {
		return installedSeq{}, err
	}
	return record, nil
}

func (h *Handler) verifyChannel(ctx context.Context, release releaseattest.Release, artifact releaseattest.Artifact) (Binary, error) {
	if h.Registry == nil {
		return Binary{}, errors.New("this host has no regional release channel")
	}
	registry, err := h.Registry(ctx)
	if err != nil {
		return Binary{}, err
	}
	if err := ocirelease.Verify(ctx, registry, h.Attest, release); err != nil {
		return Binary{}, err
	}
	return Binary{URL: artifact.URL, SHA256: artifact.SHA256}, nil
}

func (h *Handler) checkSeq(release releaseattest.Release) error {
	installed, err := readSeq(h.SeqFile)
	if err != nil {
		return fmt.Errorf("installed seq unreadable: %w", err)
	}
	if release.Seq < installed.Seq || release.Seq == installed.Seq && release.Tag() != installed.Tag {
		return fmt.Errorf("%w: channel seq %d (%s) is not newer than the installed seq %d (%s); a replayed or rolled-back channel document is refused",
			releaseattest.ErrRefused, release.Seq, release.Tag(), installed.Seq, installed.Tag)
	}
	return nil
}

func (h *Handler) recordSeq(release releaseattest.Release, binary Binary) error {
	if err := writeJSON(h.SeqFile, installedSeq{Seq: release.Seq, Tag: release.Tag(), SHA256: binary.SHA256}); err != nil {
		return fmt.Errorf("installed seq not saved: %w", err)
	}
	return nil
}

func RecordChannelSeq(state string, seq uint64) error {
	if seq == 0 {
		return nil
	}
	path := channelSeqFile(state)
	if data, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(data)) == strconv.FormatUint(seq, 10) {
		return nil
	}
	return writeState(path, []byte(strconv.FormatUint(seq, 10)))
}

func committedSeq(state, binary string) (uint64, error) {
	record, err := readSeq(seqFile(state))
	if err != nil || record.Seq == 0 {
		return 0, err
	}
	var pending trial
	if present, err := readRecord(trialFile(state), &pending); present || err != nil {
		return 0, err
	}
	running, err := binaryIdentity(binary)
	if err != nil || running.SHA256 != record.SHA256 {
		return 0, err
	}
	return record.Seq, nil
}

func releaseSeqs(state, binary string) (uint64, uint64, error) {
	installed, err := committedSeq(state, binary)
	if err != nil {
		return 0, 0, err
	}
	data, err := os.ReadFile(channelSeqFile(state))
	if errors.Is(err, os.ErrNotExist) {
		return installed, 0, nil
	}
	if err != nil {
		return installed, 0, err
	}
	channel, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return installed, channel, err
}
