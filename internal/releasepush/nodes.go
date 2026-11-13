package releasepush

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/nodelist"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const SubjectNodes = protocol.ReleaseNodes

type NodesRelease struct {
	Kind     string `json:"kind"`
	SHA      string `json:"sha"`
	Artifact Binary `json:"artifact"`
	Token    string `json:"token"`
}

func NodesURL(sha string) string {
	return "https://raw.githubusercontent.com/" + orchRepository + "/" + sha + "/deploy/m1/nodes.json"
}

func (h *Handler) nodes(ctx context.Context, data []byte) Reply {
	var release NodesRelease
	if err := protocol.DecodeStrict(data, &release, 32<<10); err != nil {
		return rejected(err)
	}
	if release.Kind != "nodes" || !hex40.MatchString(release.SHA) || !hex64.MatchString(release.Artifact.SHA256) {
		return rejected(errors.New("invalid nodes artifact"))
	}
	claims, err := h.Verifier.Verify(ctx, release.Token)
	if err != nil {
		return rejected(err)
	}
	if claims.Repository != orchRepository || claims.JobWorkflowRef != orchWorkflow || claims.SHA != release.SHA {
		return rejected(errors.New("token is not for this ts-orchestrator node list"))
	}
	if release.Artifact.URL != NodesURL(claims.SHA) {
		return rejected(errors.New("node list must be the signed commit's deploy/m1/nodes.json"))
	}
	if h.NodeList == nil {
		return rejected(errors.New("node list store is unavailable"))
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, NodesURL(claims.SHA), nil)
	if err != nil {
		return rejected(err)
	}
	response, err := h.Client.Do(request)
	if err != nil {
		return rejected(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return rejected(fmt.Errorf("node list download: %s", response.Status))
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, nodelist.MaxBytes+1))
	if err != nil {
		return rejected(err)
	}
	if len(wire) > nodelist.MaxBytes {
		return rejected(errors.New("node list is too large"))
	}
	sum := sha256.Sum256(wire)
	if hex.EncodeToString(sum[:]) != release.Artifact.SHA256 {
		return rejected(errors.New("node list sha256 differs"))
	}
	list, err := nodelist.Decode(wire)
	if err != nil {
		return rejected(err)
	}
	run, err := strconv.ParseUint(claims.RunID, 10, 64)
	if err != nil {
		return rejected(err)
	}
	changed, err := h.NodeList.Apply(list, run)
	if errors.Is(err, nodelist.ErrStale) {
		return Reply{State: "stale", Version: strconv.FormatUint(h.NodeList.Snapshot().Sequence, 10)}
	}
	if err != nil {
		return rejected(err)
	}
	state := "current"
	if changed {
		state = "updated"
	}
	if h.Relay != nil {
		h.Relay(data)
	}
	return Reply{State: state, Version: strconv.FormatUint(list.Sequence, 10)}
}

func SignNodes(ctx context.Context, sha, path string) (NodesRelease, error) {
	if !hex40.MatchString(sha) {
		return NodesRelease{}, errors.New("sha must be 40 lowercase hex")
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		return NodesRelease{}, err
	}
	if _, err := nodelist.Decode(wire); err != nil {
		return NodesRelease{}, err
	}
	token, err := MintToken(ctx)
	if err != nil {
		return NodesRelease{}, err
	}
	_, err = tokenRunID(token)
	if err != nil {
		return NodesRelease{}, err
	}
	sum := sha256.Sum256(wire)
	return NodesRelease{Kind: "nodes", SHA: sha, Artifact: Binary{URL: NodesURL(sha), SHA256: hex.EncodeToString(sum[:])}, Token: token}, nil
}

func NodesCLI(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 3 && args[0] == "sign" {
		release, err := SignNodes(ctx, args[1], args[2])
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(release)
	}
	var release NodesRelease
	regionsPath := "deploy/m1/regions.json"
	switch {
	case (len(args) == 3 || len(args) == 4) && args[0] == "publish":
		wire, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		list, err := nodelist.Decode(wire)
		if err != nil {
			return err
		}
		if len(list.Nodes) == 0 {
			return nil
		}
		release, err = SignNodes(ctx, args[1], args[2])
		if err != nil {
			return err
		}
		if len(args) == 4 {
			regionsPath = args[3]
		}
	case (len(args) == 2 || len(args) == 3) && args[0] == "push":
		wire, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		if err := protocol.DecodeStrict(wire, &release, 32<<10); err != nil {
			return err
		}
		if len(args) == 3 {
			regionsPath = args[2]
		}
	default:
		return errors.New("usage: ts-orch release nodes sign SHA LIST | push ENVELOPE [REGIONS] | publish SHA LIST [REGIONS]")
	}
	regions, err := LoadRegions(regionsPath)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(release)
	if err != nil {
		return err
	}
	for _, region := range regions {
		conn, err := Dial(region, release.Token)
		if err != nil {
			return err
		}
		reply, err := request(ctx, conn, SubjectNodes, payload, healthRequestTimeout)
		conn.Close()
		if err != nil {
			return err
		}
		if err := json.NewEncoder(out).Encode(struct {
			Region string `json:"region"`
			Reply
		}{region.Region, reply}); err != nil {
			return err
		}
		if reply.Error != "" {
			return errors.New(reply.Error)
		}
	}
	return nil
}

func (h *Handler) workerRelease(ctx context.Context, data []byte) Reply {
	var artifact struct{ Kind string }
	if err := json.Unmarshal(data, &artifact); err != nil {
		return rejected(err)
	}
	if artifact.Kind == "nodes" {
		return h.nodes(ctx, data)
	}
	return h.orch(ctx, data)
}
