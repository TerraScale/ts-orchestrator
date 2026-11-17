package releaseclient

import (
	"encoding/base64"
	"encoding/json"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"regexp"
	"time"
)

type Reply = releasepush.Reply
type Claims = releasepush.Claims
type Binary = releasepush.Binary
type OrchRelease = releasepush.OrchRelease
type AppRelease = releasepush.AppRelease
type MeshRequest = releasepush.MeshRequest
type HostVersion = releasepush.HostVersion
type HealthRequest = releasepush.HealthRequest
type Nudge = releasepush.Nudge

const (
	assetPrefix          = "terrascale-orchestrator-linux-"
	maxTokenSize         = 16 << 10
	healthRequestTimeout = 30 * time.Second
	fetchTimeout         = 10 * time.Second
	clockSkew            = time.Minute
	HandlerWait          = releasepush.HandlerWait
	WorkerReplyWait      = releasepush.WorkerReplyWait
	WorkerReadyWait      = releasepush.WorkerReadyWait
	Audience             = releasepush.Audience
	SubjectVersion       = releasepush.SubjectVersion
	SubjectHealth        = releasepush.SubjectHealth
	SubjectOrch          = releasepush.SubjectOrch
	SubjectApp           = releasepush.SubjectApp
	SubjectState         = releasepush.SubjectState
	SubjectNudge         = releasepush.SubjectNudge
	RefusalHost          = releasepush.RefusalHost
	RefusalFence         = releasepush.RefusalFence
)

var hex40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
var appImage = regexp.MustCompile(`^ghcr\.io/terrascale/([a-z0-9][a-z0-9._-]{0,127})@sha256:[0-9a-f]{64}$`)
var ReleaseTag = releasepush.ReleaseTag
var ReleaseURL = releasepush.ReleaseURL

type Verifier = releasepush.Verifier

var NewVerifier = releasepush.NewVerifier

var runID = regexp.MustCompile(`^[0-9]{1,20}$`)
var RefusedOn = releasepush.RefusedOn

func decodeSegment(segment string, into any) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, into)
}
