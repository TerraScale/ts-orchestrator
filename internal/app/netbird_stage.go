package app

import (
	"context"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/artifact"
	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const netbirdStageKind = "netbird.artifact.stage"

type netbirdStageRequest struct {
	Architecture string `json:"architecture"`
	Digest       string `json:"digest"`
	Size         int64  `json:"size"`
	Verify       bool   `json:"verify"`
}

type netbirdStageReply struct {
	Version      string `json:"version,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	Digest       string `json:"digest,omitempty"`
	Size         int64  `json:"size,omitempty"`
	Staged       bool   `json:"staged"`
	Error        string `json:"error,omitempty"`
}

func netbirdStagePin(services *specRegistry, request netbirdStageRequest) (string, error) {
	if services == nil || request.Size < 64 || request.Size > client.MaxBinaryBytes || !client.SHA256Pattern.MatchString(request.Digest) {
		return "", errors.New("invalid NetBird staging request")
	}
	pin := services.netbird()
	if pin == nil {
		return "", errors.New("cell spec has no NetBird pin")
	}
	if err := client.ValidatePin(pin.Pin); err != nil {
		return "", err
	}
	archive, err := pin.Pin.Archive(request.Architecture)
	if err != nil {
		return "", err
	}
	if archive.BinarySHA256 != request.Digest {
		return "", errors.New("NetBird binary SHA-256 is not authorized by the active cell pin")
	}
	return pin.Pin.Version, nil
}

func verifyNetBirdArtifact(ctx context.Context, js jetstream.JetStream, store jetstream.ObjectStore,
	digest, architecture string, size int64,
) error {
	return verifyNetBirdArtifactContents(ctx, digest, architecture, func(dst io.Writer) error {
		return artifact.ReadVerified(ctx, js, store, delivery.ArtifactBucket, "sha256-"+digest, digest,
			size, client.MaxBinaryBytes, dst)
	})
}

func verifyNetBirdArtifactContents(ctx context.Context, digest, architecture string, read func(io.Writer) error) error {
	file, err := os.CreateTemp("", "ts-netbird-verify-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if err := read(file); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := client.VerifyBinary(file.Name(), digest, architecture); err != nil {
		return err
	}
	return ctx.Err()
}

// serveNetBirdStage authorizes exact public upstream bytes with the active
// signed cell pin. It creates no build-source claim or workload admission.
// Requests use the existing authenticated operator registration transport.
func serveNetBirdStage(ctx context.Context, wire []byte, policy signerPolicy, fencer authority.Fencer,
	services *specRegistry, conn *nats.Conn,
) (netbirdStageReply, error) {
	envelope, _, err := verifyCellRequest(wire, policy, fencer)
	if err != nil {
		return netbirdStageReply{}, err
	}
	if envelope.Kind != netbirdStageKind {
		return netbirdStageReply{}, errors.New("invalid NetBird staging request kind")
	}
	var request netbirdStageRequest
	if err := protocol.DecodeStrict(envelope.Payload, &request, 4096); err != nil {
		return netbirdStageReply{}, err
	}
	version, err := netbirdStagePin(services, request)
	if err != nil {
		return netbirdStageReply{}, err
	}
	if err := fencer.Guard(ctx, envelope.Epoch); err != nil {
		return netbirdStageReply{}, err
	}
	reply := netbirdStageReply{Version: version, Architecture: request.Architecture, Digest: request.Digest, Size: request.Size}
	if !request.Verify {
		return reply, nil
	}
	js, err := jetstream.New(conn)
	if err != nil {
		return netbirdStageReply{}, err
	}
	store, err := js.ObjectStore(ctx, delivery.ArtifactBucket)
	if err != nil {
		return netbirdStageReply{}, err
	}
	name := "sha256-" + request.Digest
	if err := verifyNetBirdArtifact(ctx, js, store, request.Digest, request.Architecture, request.Size); err != nil {
		return netbirdStageReply{}, err
	}
	if _, err := netbirdStagePin(services, request); err != nil {
		return netbirdStageReply{}, err
	}
	if err := fencer.Guard(ctx, envelope.Epoch); err != nil {
		return netbirdStageReply{}, err
	}
	legacy, err := conn.JetStream()
	if err != nil {
		return netbirdStageReply{}, err
	}
	// Even an existing object is touched: a collector that chose it before
	// this pin became active must not delete the new reference afterward.
	if err := artifact.Touch(ctx, legacy, delivery.ArtifactBucket, name); err != nil {
		return netbirdStageReply{}, err
	}
	if err := fencer.Guard(ctx, envelope.Epoch); err != nil {
		return netbirdStageReply{}, err
	}
	if _, err := netbirdStagePin(services, request); err != nil {
		return netbirdStageReply{}, err
	}
	reply.Staged = true
	return reply, nil
}

func requestNetBirdStage(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	request netbirdStageRequest,
) (netbirdStageReply, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return netbirdStageReply{}, err
	}
	wire, err := requestLeader(ctx, cfg, runtime, netbirdStageKind, "netbird-stage", payload)
	if err != nil {
		return netbirdStageReply{}, err
	}
	var reply netbirdStageReply
	if err := protocol.DecodeStrict(wire, &reply, 4096); err != nil {
		return netbirdStageReply{}, err
	}
	if reply.Error != "" {
		return netbirdStageReply{}, errors.New(reply.Error)
	}
	if reply.Digest != request.Digest || reply.Architecture != request.Architecture || reply.Size != request.Size || reply.Staged != request.Verify {
		return netbirdStageReply{}, errors.New("controller returned a different NetBird staging receipt")
	}
	return reply, nil
}

func snapshotNetBirdStage(ctx context.Context, path, architecture string) (*os.File, string, int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", 0, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, "", 0, err
	}
	source := os.NewFile(uintptr(fd), path)
	defer source.Close()
	info, err := source.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 64 || info.Size() > client.MaxBinaryBytes {
		return nil, "", 0, errors.New("NetBird staging source must be a bounded regular ELF executable")
	}
	snapshot, err := os.CreateTemp("", "ts-netbird-upload-*")
	if err != nil {
		return nil, "", 0, err
	}
	discard := func(err error) (*os.File, string, int64, error) {
		_ = snapshot.Close()
		_ = os.Remove(snapshot.Name())
		return nil, "", 0, err
	}
	size, err := io.Copy(snapshot, io.LimitReader(source, client.MaxBinaryBytes+1))
	if err != nil || size < 64 || size > client.MaxBinaryBytes {
		return discard(errors.Join(errors.New("cannot snapshot bounded NetBird staging source"), err))
	}
	digest, err := client.SHA256(snapshot.Name())
	if err != nil {
		return discard(err)
	}
	if err := client.VerifyBinary(snapshot.Name(), digest, architecture); err != nil {
		return discard(err)
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		return discard(err)
	}
	if err := ctx.Err(); err != nil {
		return discard(err)
	}
	return snapshot, digest, size, nil
}

func operatorNetBirdStage(ctx context.Context, cfg Config, runtime *natscell.Runtime,
	path, architecture string, output io.Writer,
) error {
	snapshot, digest, size, err := snapshotNetBirdStage(ctx, path, architecture)
	if err != nil {
		return err
	}
	defer os.Remove(snapshot.Name())
	defer snapshot.Close()
	request := netbirdStageRequest{Architecture: architecture, Digest: digest, Size: size}
	if _, err := requestNetBirdStage(ctx, cfg, runtime, request); err != nil {
		return err
	}
	name := "sha256-" + digest
	staging, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	legacy, err := runtime.Conn().JetStream()
	if err != nil {
		return err
	}
	subject := "$O." + delivery.ArtifactBucket + ".M." + base64.URLEncoding.EncodeToString([]byte(name))
	meta, err := legacy.GetLastMsg("OBJ_"+delivery.ArtifactBucket, subject, nats.Context(staging))
	if err != nil && !errors.Is(err, nats.ErrMsgNotFound) {
		return err
	}
	var existing jetstream.ObjectInfo
	if meta != nil {
		if json.Unmarshal(meta.Data, &existing) != nil {
			err = artifact.ErrInvalid
		} else {
			err = verifyNetBirdArtifactContents(staging, digest, architecture, func(dst io.Writer) error {
				return artifact.ReadVerifiedAuthoritative(staging, runtime.JetStream(), &existing,
					delivery.ArtifactBucket, name, digest, size, client.MaxBinaryBytes, dst)
			})
		}
	}
	if err != nil && !errors.Is(err, artifact.ErrInvalid) && !errors.Is(err, jetstream.ErrObjectNotFound) &&
		!errors.Is(err, nats.ErrMsgNotFound) {
		return err
	}
	if err != nil {
		stream, err := runtime.JetStream().Stream(staging, "OBJ_"+delivery.ArtifactBucket)
		if err != nil {
			return err
		}
		state, err := stream.Info(staging)
		if err != nil {
			return err
		}
		if state.Config.MaxBytes <= 0 {
			return errors.New("NetBird staging requires the bounded regional artifact store")
		}
		if state.State.Bytes >= uint64(state.Config.MaxBytes) || uint64(size) > uint64(state.Config.MaxBytes)-state.State.Bytes {
			return delivery.ErrArtifactStoreFull
		}
		if meta != nil {
			if err := repairNetBirdStageMetadata(staging, legacy, meta, name); err != nil {
				return err
			}
		}
		if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
			return err
		}
		// The legacy uploader reads metadata from the leader; a follower could
		// still see the undeleted revision and attempt an unauthorized purge.
		uploader, err := legacy.ObjectStore(delivery.ArtifactBucket)
		if err != nil {
			return err
		}
		if _, err := uploader.Put(&nats.ObjectMeta{Name: name}, snapshot, nats.Context(staging)); err != nil {
			return fmt.Errorf("stage pinned NetBird in regional artifact store: %w", err)
		}
	}
	request.Verify = true
	reply, err := requestNetBirdStage(ctx, cfg, runtime, request)
	if err != nil {
		return err
	}
	return printJSON(output, reply)
}

// Operators cannot purge old chunks. Tombstone only the corrupt revision
// verified above, so Put skips purging and orphan chunks stay quota charged.
func repairNetBirdStageMetadata(ctx context.Context, legacy nats.JetStreamContext, meta *nats.RawStreamMsg, name string) error {
	body, err := json.Marshal(jetstream.ObjectInfo{ObjectMeta: jetstream.ObjectMeta{Name: name},
		Bucket: delivery.ArtifactBucket, Deleted: true})
	if err != nil {
		return err
	}
	message := nats.NewMsg(meta.Subject)
	message.Data = body
	message.Header.Set(nats.MsgRollup, nats.MsgRollupSubject)
	_, err = legacy.PublishMsg(message, nats.Context(ctx), nats.ExpectLastSequencePerSubject(meta.Sequence))
	return err
}
