package app

import (
	"context"
	"errors"

	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// The local watcher may not have adopted a committed root rotation yet.
func rootTrustHeadCurrent(ctx context.Context, js jetstream.JetStream, roots *rootRegistry, head string) error {
	if ctx == nil || js == nil || js.Conn() == nil || roots == nil || head == "" {
		return errors.New("root authority requires its current broker leader")
	}
	options := js.Options()
	var opts []nats.JSOpt
	if options.Domain != "" {
		opts = append(opts, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		opts = append(opts, nats.APIPrefix(options.APIPrefix))
	}
	reader, err := js.Conn().JetStream(opts...)
	if err != nil {
		return err
	}
	subject := "$KV." + rootChainBucket + "." + rootChainKey
	latest, err := reader.GetLastMsg("KV_"+rootChainBucket, subject, nats.Context(ctx))
	if err != nil {
		return err
	}
	if latest == nil || latest.Subject != subject || latest.Sequence == 0 || latest.Header.Get("KV-Operation") != "" || latest.Header.Get(jetstream.MarkerReasonHeader) != "" ||
		len(latest.Data) == 0 || len(latest.Data) > trust.MaxRootChainBytes {
		return errors.New("root authority has no current leader record")
	}
	chain, err := trust.DecodeRootChain(latest.Data)
	if err != nil {
		return err
	}
	verified, err := trust.VerifyRootChain(roots.genesis, roots.identity, chain)
	if err != nil {
		return err
	}
	if verified.Head != head || roots.reply("").Head != head {
		return errors.New("root authority changed during recipient verification")
	}
	return ctx.Err()
}
