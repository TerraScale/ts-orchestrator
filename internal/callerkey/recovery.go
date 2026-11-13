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
	Secret  bool
	Version bool
}

func waiting(intent *Intent, reason string, cause error) error {
	from := intent.Started.Add(settleWindow).UTC().Format(time.RFC3339Nano)
	if cause != nil {
		reason += ": " + cause.Error()
	}
	return fmt.Errorf("waiting for %s; metadata absence can be decided by a new recover from %s; %s %s intent %s retained", reason, from, intent.Operation, intent.Kid, intent.ID)
}

func privateHalf(ctx context.Context, store Store, target Target, name string, intent *Intent) (PrivateState, bool, error) {
	var version int64
	var versionName string
	if intent != nil {
		version, versionName = intent.PrivateVersion, intent.VersionName
	}
	metadata, err := store.Metadata(ctx, target, name, version, versionName)
	if err != nil {
		if intent != nil {
			return PrivateState{}, false, waiting(intent, name+" management metadata", err)
		}
		return PrivateState{}, false, err
	}
	exists := metadata.Secret && metadata.Version
	if !exists && intent != nil {
		if time.Now().Before(intent.Started.Add(settleWindow)) {
			subject := name + " creation"
			if version > 0 {
				subject = fmt.Sprintf("%s version %d", name, version)
			} else if versionName != "" {
				subject = name + " version " + versionName
			}
			return PrivateState{}, false, waiting(intent, subject+" to settle", nil)
		}
		second, err := store.Metadata(ctx, target, name, version, versionName)
		if err != nil || second != metadata {
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

func cancelPending(ctx context.Context, store Store, target Target, name string, state PrivateState, intent *Intent) error {
	for _, v := range state.Versions {
		if v.Version != intent.PrivateVersion {
			continue
		}
		if v.Version == state.Current.Version {
			return errors.New("cannot cancel the current private key")
		}
		if v.Pending {
			if err := store.Stage(ctx, target, name, state, state.Current.Value, "cancel."+intent.Kid); err != nil {
				return err
			}
			after, _, err := privateHalf(ctx, store, target, name, intent)
			if err != nil {
				return err
			}
			defer after.Clear()
			state = after
		}
		return store.Discard(ctx, target, name, state, intent.PrivateVersion)
	}
	return nil
}

func recoverOperation(ctx context.Context, out io.Writer, store Store, targets []Target, snapshots []Snapshot, registries []Registry, callers map[string]Caller, highWater map[string]uint64, intent *Intent) error {
	if !slices.Contains([]string{"add", "activate", "retire", "cancel"}, intent.Operation) || intent.ID == "" || intent.Started.IsZero() || !kidRE.MatchString(intent.Kid) && !operatorRE.MatchString(intent.Kid) {
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
	if intent.Operation == "activate" && current != intent.Kid && pending == 0 {
		return waiting(intent, name+" matching pending or current version", nil)
	}
	if (intent.Operation == "retire" || intent.Operation == "cancel") && current == intent.Kid {
		return operationError(intent, errors.New("cannot remove the current private key"))
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
		for _, r := range registries {
			if !slices.ContainsFunc(r.Callers, func(c Caller) bool { return c.Kid == intent.Kid }) {
				return operationError(intent, errors.New("activation requires the public key in every region"))
			}
		}
		if current != intent.Kid {
			if err := store.Activate(ctx, selected, name, state, pending); err != nil {
				return operationError(intent, err)
			}
		}
	case "cancel":
		if err := cancelPending(ctx, store, selected, name, state, intent); err != nil {
			return operationError(intent, err)
		}
		advance(highWater, intent.Kid)
		delete(callers, intent.Kid)
	case "retire":
		if pending != 0 {
			return operationError(intent, errors.New("cannot retire a pending private key without cancellation"))
		}
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
