package releaseattest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

const (
	ChannelDocument = "channel.json"
	ChannelBundle   = "channel.sigstore.json"
)

var blobDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Channel struct {
	Seq         uint64    `json:"seq"`
	SHA         string    `json:"sha"`
	Run         string    `json:"run"`
	Artifact    string    `json:"artifact"`
	PublishedAt time.Time `json:"published_at"`
}

type SignedChannel struct {
	Document []byte `json:"document"`
	Bundle   []byte `json:"bundle"`
}

func (c Channel) Tag() string { return Tag(c.SHA, c.Run) }

func ParseChannel(document []byte) (Channel, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var channel Channel
	if err := decoder.Decode(&channel); err != nil || decoder.More() {
		return Channel{}, fmt.Errorf("%w: channel document unreadable: %v", ErrRefused, err)
	}
	switch {
	case channel.Seq == 0:
		return channel, fmt.Errorf("%w: channel document has no seq", ErrRefused)
	case !sha40.MatchString(channel.SHA) || !runID.MatchString(channel.Run):
		return channel, fmt.Errorf("%w: channel sha must be 40 lowercase hex and run a number", ErrRefused)
	case !blobDigest.MatchString(channel.Artifact):
		return channel, fmt.Errorf("%w: channel artifact %q is not a sha256 digest", ErrRefused, channel.Artifact)
	case channel.PublishedAt.IsZero():
		return channel, fmt.Errorf("%w: channel document has no published_at", ErrRefused)
	}
	return channel, nil
}

func (v Verifier) Channel(signed SignedChannel) (Channel, error) {
	channel, err := ParseChannel(signed.Document)
	if err != nil {
		return channel, err
	}
	subjects, err := v.subjects(signed.Bundle, channel.SHA, channel.Run)
	if err != nil {
		return channel, err
	}
	sum := sha256.Sum256(signed.Document)
	if subjects[ChannelDocument] != hex.EncodeToString(sum[:]) {
		return channel, fmt.Errorf("%w: channel document seq %d differs from its attestation", ErrRefused, channel.Seq)
	}
	return channel, nil
}

func (r Release) validateChannel() error {
	if r.Seq == 0 {
		return fmt.Errorf("%w: a channel release needs its seq", ErrRefused)
	}
	if len(r.Binaries) == 0 || r.Bundle == "" {
		return fmt.Errorf("%w: no binaries", ErrRefused)
	}
	for arch, binary := range r.Binaries {
		if binary.URL == "" || !hex64.MatchString(binary.SHA256) {
			return fmt.Errorf("%w: %s needs a registry blob and its sha256", ErrRefused, arch)
		}
	}
	return nil
}
