package callerkey

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

type PrivateMetadata struct {
	Secret   bool
	Version  bool
	StoreNow time.Time
}

func waiting(intent *Intent, reason string, cause error) error {
	until := intent.created.Add(settleWindow).UTC().Format(time.RFC3339Nano)
	if cause != nil {
		reason += ": " + cause.Error()
	}
	return fmt.Errorf("waiting until %s for %s; %s %s intent %s retained", until, reason, intent.Operation, intent.Kid, intent.ID)
}

func privateHalf(ctx context.Context, store Store, target Target, name string, intent *Intent) (PrivateState, bool, error) {
	var version int64
	var versionName string
	if intent != nil && intent.Operation != "retire" {
		version, versionName = intent.PrivateVersion, intent.VersionName
	}
	metadata, err := store.Metadata(ctx, target, name, version, versionName)
	if err != nil {
		if intent != nil {
			return PrivateState{}, false, waiting(intent, name+" management metadata", err)
		}
		return PrivateState{}, false, err
	}
	if !metadata.Secret && intent != nil && intent.Operation == "retire" {
		state, readErr := store.Private(ctx, target, name)
		if readErr == nil && state.Current.Version > 0 {
			return state, true, nil
		}
		state.Clear()
	}
	exists := metadata.Secret && metadata.Version
	if !exists && intent != nil {
		if intent.created.IsZero() || metadata.StoreNow.IsZero() || !metadata.StoreNow.After(intent.created.Add(settleWindow)) {
			return PrivateState{}, false, waiting(intent, name+" creation to settle on the store clock", nil)
		}
		second, err := store.Metadata(ctx, target, name, version, versionName)
		if err != nil || second.Secret != metadata.Secret || second.Version != metadata.Version || !second.StoreNow.After(intent.created.Add(settleWindow)) || second.StoreNow.Before(metadata.StoreNow) {
			return PrivateState{}, false, waiting(intent, name+" two agreeing management metadata reads", err)
		}
	}
	if !metadata.Secret {
		return PrivateState{}, false, nil
	}
	state, err := store.Private(ctx, target, name)
	if err != nil && intent != nil {
		return PrivateState{}, false, waiting(intent, name+" existing private version to become readable", err)
	}
	if err == nil && intent != nil {
		for _, v := range state.Versions {
			id, err := privateKid(v.Snapshot)
			if err != nil {
				state.Clear()
				return PrivateState{}, false, err
			}
			exists = exists || id == intent.Kid
		}
	}
	return state, exists, err
}

func cancelPending(ctx context.Context, out io.Writer, store Store, target Target, name string, state PrivateState, intent *Intent, exists bool) error {
	if deletion, ok := state.Scheduled[intent.PrivateVersion]; ok {
		if intent.PrivateVersion == state.Current.Version {
			return errors.New("cannot cancel the current private key")
		}
		_, err := fmt.Fprintln(out, name, intent.Kid, "deletion scheduled", deletion.UTC().Format(time.RFC3339))
		return err
	}
	for _, v := range state.Versions {
		if v.Version != intent.PrivateVersion {
			continue
		}
		if v.Version == state.Current.Version {
			return errors.New("cannot cancel the current private key")
		}
		if v.Pending {
			if err := privateWrite(ctx, intent, func(writeCtx context.Context) error {
				return store.Stage(writeCtx, target, name, state, state.Current.Value, "cancel."+intent.Kid)
			}); err != nil {
				return err
			}
			after, err := store.Private(ctx, target, name)
			if err != nil {
				return err
			}
			defer after.Clear()
			state = after
		}
		var deletion time.Time
		err := privateWrite(ctx, intent, func(writeCtx context.Context) (err error) {
			deletion, err = store.Discard(writeCtx, target, name, state, intent.PrivateVersion)
			return
		})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, name, intent.Kid, "deletion scheduled", deletion.UTC().Format(time.RFC3339))
		return err
	}
	if exists {
		return errors.New("cancellation version missing from coherent inventory; run caller-key recover")
	}
	return nil
}

func retirementReady(registries []Registry, intent *Intent, state PrivateState) error {
	current, err := privateKid(state.Current)
	if err != nil {
		return err
	}
	if current == "" {
		return nil
	}
	if current == intent.Kid {
		return errors.New("cannot remove the current private key")
	}
	parts := kidRE.FindStringSubmatch(intent.Replacement)
	if len(parts) != 4 || parts[1] != intent.Caller || parts[2] != intent.Cell || current != intent.Replacement {
		return errors.New("retiring a stored key requires --replacement-kid naming the current key for that caller and region")
	}
	for _, registry := range registries {
		if !slices.ContainsFunc(registry.Callers, func(c Caller) bool { return c.Kid == current }) {
			return errors.New("replacement key must be listed in every region")
		}
	}
	for _, v := range state.Versions {
		id, err := privateKid(v.Snapshot)
		if err != nil {
			return err
		}
		if id == intent.Kid && v.Pending {
			return errors.New("cannot retire a pending private key without cancellation")
		}
	}
	return nil
}

func recoverOperation(ctx context.Context, out io.Writer, store Store, targets []Target, snapshots []Snapshot, registries []Registry, callers map[string]Caller, highWater map[string]uint64, intent *Intent) error {
	if !slices.Contains([]string{"add", "activate", "retire", "cancel"}, intent.Operation) || intent.ID == "" || intent.DispatchBound != dispatchBound.String() || !kidRE.MatchString(intent.Kid) && !operatorRE.MatchString(intent.Kid) {
		return errors.New("invalid operation record")
	}
	var selected Target
	for _, t := range targets {
		if t.Cell == intent.Cell {
			selected = t
		}
	}
	state := PrivateState{}
	exists := false
	name := secretName(intent.Caller, intent.Cell)
	if kidRE.MatchString(intent.Kid) {
		if selected.Cell == "" {
			return errors.New("operation region is not deployed")
		}
		var err error
		state, exists, err = privateHalf(ctx, store, selected, name, intent)
		if err != nil {
			return err
		}
	}
	defer state.Clear()
	current, err := privateKid(state.Current)
	if err != nil {
		return err
	}
	var pending int64
	for _, v := range state.Versions {
		id, err := privateKid(v.Snapshot)
		if err != nil {
			return err
		}
		if id == intent.Kid && v.Pending {
			pending = v.Version
		}
	}
	outcome := "finished forward"
	if intent.Operation == "add" && exists && current != intent.Kid && pending == 0 {
		return waiting(intent, name+" matching private contents", nil)
	}
	if intent.Operation == "activate" && current != intent.Kid {
		if pending == 0 {
			return waiting(intent, name+" matching pending or current version", nil)
		}
		if err := activationReady(registries, intent.Kid); err != nil {
			intent.Operation = "cancel"
			intent.PrivateVersion = pending
			outcome = "activation no longer valid; cancelled pending key"
		}
	}
	if (intent.Operation == "retire" || intent.Operation == "cancel") && current == intent.Kid {
		return operationError(intent, errors.New("cannot remove the current private key"))
	}
	if intent.Operation == "retire" && kidRE.MatchString(intent.Kid) {
		if err := retirementReady(registries, intent, state); err != nil {
			return operationError(intent, err)
		}
	}
	if err := writeIntent(ctx, store, targets, snapshots, registries, intent); err != nil {
		return err
	}
	switch intent.Operation {
	case "add":
		advance(highWater, intent.Kid)
		if !exists {
			delete(callers, intent.Kid)
			outcome = "finished backward"
		} else if _, ok := callers[intent.Kid]; !ok {
			return operationError(intent, errors.New("stored key has no public entry"))
		}
	case "activate":
		intent.validUntil = callers[intent.Kid].NotAfter.Add(-minimumLifetime)
		if current != intent.Kid {
			if err := activationReady(registries, intent.Kid); err != nil {
				intent.Operation = "cancel"
				intent.PrivateVersion = pending
				if err := writeIntent(ctx, store, targets, snapshots, registries, intent); err != nil {
					return err
				}
				if err := cancelPending(ctx, out, store, selected, name, state, intent, exists); err != nil {
					return operationError(intent, err)
				}
				advance(highWater, intent.Kid)
				delete(callers, intent.Kid)
				outcome = "activation no longer valid; cancelled pending key"
			} else if err := privateWrite(ctx, intent, func(writeCtx context.Context) error { return store.Activate(writeCtx, selected, name, state, pending) }); err != nil {
				return operationError(intent, err)
			}
		}
	case "cancel":
		if err := cancelPending(ctx, out, store, selected, name, state, intent, exists); err != nil {
			return operationError(intent, err)
		}
		advance(highWater, intent.Kid)
		delete(callers, intent.Kid)
	case "retire":
		advance(highWater, intent.Kid)
		delete(callers, intent.Kid)
	}
	if intent.Operation != "activate" {
		r := mergedRegistry(callers, highWater, intent)
		for i := range targets {
			if err := writeRegistry(ctx, store, targets[i], &snapshots[i], r); err != nil {
				return operationError(intent, err)
			}
			registries[i] = r
		}
	}
	if err := clearIntent(ctx, store, targets, snapshots, registries); err != nil {
		return operationError(intent, err)
	}
	_, err = fmt.Fprintln(out, "recovered", intent.Operation, intent.Kid, intent.ID, outcome)
	return err
}

func sameIntent(a, b *Intent) bool {
	x, y := *a, *b
	if x.Operation == "activate" && y.Operation == "cancel" {
		x.Operation = "cancel"
	}
	if y.Operation == "activate" && x.Operation == "cancel" {
		y.Operation = "cancel"
	}
	return sameJSON(x, y)
}
