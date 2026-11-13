package callerkey

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

func privateWrite(ctx context.Context, write func(context.Context) error) error {
	writeCtx, cancel := context.WithTimeout(ctx, privateRequestTimeout)
	defer cancel()
	return write(writeCtx)
}

func cancellationKnown(state PrivateState, intent *Intent) error {
	if intent.PrivateVersion < 1 || intent.PrivateVersion == state.Current.Version {
		return errors.New("cancellation requires an identified non-current private version")
	}
	if _, ok := state.Scheduled[intent.PrivateVersion]; ok {
		return nil
	}
	for _, version := range state.Versions {
		if version.Version == intent.PrivateVersion {
			id, err := privateKid(version.Snapshot)
			if err != nil || id != intent.Kid {
				return errors.New("cancellation version does not identify the recorded key")
			}
			return nil
		}
	}
	return errors.New("cancellation version missing from coherent inventory; run caller-key recover")
}

func cancelPending(ctx context.Context, out io.Writer, store Store, target Target, name string, state PrivateState, intent *Intent) error {
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
		id, err := privateKid(v.Snapshot)
		if err != nil || id != intent.Kid {
			return errors.New("cancellation version does not identify the recorded key")
		}
		if v.Version == state.Current.Version {
			return errors.New("cannot cancel the current private key")
		}
		if v.Pending {
			if err := privateWrite(ctx, func(writeCtx context.Context) error {
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
		err = privateWrite(ctx, func(writeCtx context.Context) (err error) {
			deletion, err = store.Discard(writeCtx, target, name, state, intent.PrivateVersion)
			return
		})
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, name, intent.Kid, "deletion scheduled", deletion.UTC().Format(time.RFC3339))
		return err
	}
	return errors.New("cancellation version missing from coherent inventory; run caller-key recover")
}

func replacementReady(registries []Registry, intent *Intent, state PrivateState) error {
	current, err := privateKid(state.Current)
	if err != nil {
		return err
	}
	if current == "" {
		return errors.New("no current private secret: an orphan public entry cannot be retired until another key is current")
	}
	if current == intent.Kid {
		return errors.New("cannot remove the current private key")
	}
	parts := kidRE.FindStringSubmatch(intent.Replacement)
	if len(parts) != 4 || parts[1] != intent.Caller || parts[2] != intent.Cell || current != intent.Replacement {
		return errors.New("retiring a stored key requires --replacement-kid naming the current key for that caller and region")
	}
	public, err := publicFromPrivate(state.Current)
	if err != nil {
		return err
	}
	for _, registry := range registries {
		if !slices.ContainsFunc(registry.Callers, func(c Caller) bool { return c.Kid == current && c.JWK == public.JWK }) {
			return errors.New("replacement key must be listed with the same public key in every region")
		}
	}
	return nil
}

func retirementReady(registries []Registry, intent *Intent, state PrivateState) error {
	if err := replacementReady(registries, intent, state); err != nil {
		return err
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
	if intent.Operation == "cancel" {
		if _, ok := state.Scheduled[intent.PrivateVersion]; !ok {
			return errors.New("cancellation requires positive evidence of scheduled deletion")
		}
	}
	return nil
}

func recoverOperation(ctx context.Context, out io.Writer, store Store, targets []Target, snapshots []Snapshot, registries []Registry, callers map[string]Caller, highWater map[string]uint64, intent *Intent) error {
	if err := validateIntent(intent, intent.Cell); err != nil {
		return err
	}
	if err := checkAddPayload(ctx, store, targets, intent); err != nil {
		return operationError(intent, err)
	}
	var selected Target
	for _, t := range targets {
		if t.Cell == intent.Cell {
			selected = t
		}
	}
	if selected.Cell == "" {
		return errors.New("operation region is not deployed")
	}
	name := secretName(intent.Caller, intent.Cell)
	state, readErr := store.Private(ctx, selected, name)
	defer state.Clear()
	if readErr != nil && intent.Operation != "add" {
		return operationError(intent, readErr)
	}
	current, err := privateKid(state.Current)
	if err != nil {
		return operationError(intent, err)
	}
	var pending int64
	for _, v := range state.Versions {
		id, err := privateKid(v.Snapshot)
		if err != nil {
			return operationError(intent, err)
		}
		if id == intent.Kid && v.Pending {
			pending = v.Version
		}
	}
	outcome := "finished forward"
	if intent.Operation == "add" {
		if intent.Entry == nil || intent.Entry.Kid != intent.Kid || intent.Entry.Caller != intent.Caller || validateCaller(*intent.Entry) != nil {
			return operationError(intent, errors.New("add intent has no valid public entry"))
		}
		callers[intent.Kid] = *intent.Entry
		if current == intent.Kid {
			outcome += "; current"
		} else if pending > 0 {
			outcome += "; pending"
		} else {
			outcome += "; public entry kept; private key not visible: run add again for a new key, or wait: retire this entry only with a current replacement"
		}
	}
	if intent.Operation == "activate" && current != intent.Kid {
		if pending == 0 {
			return operationError(intent, errors.New("matching pending or current version not visible"))
		}
		if err := activationReady(registries, intent.Kid, state); err != nil {
			intent.Operation = "cancel"
			intent.PrivateVersion = pending
			intent.Replacement = current
			outcome = "activation no longer valid; cancelled pending key"
		}
	}
	if intent.Operation == "retire" && pending > 0 {
		intent.Operation = "cancel"
		intent.PrivateVersion = pending
	}
	if intent.Operation == "cancel" || intent.Operation == "retire" {
		if err := replacementReady(registries, intent, state); err != nil {
			return operationError(intent, err)
		}
	}
	if intent.Operation == "cancel" {
		if err := cancellationKnown(state, intent); err != nil {
			return operationError(intent, err)
		}
	}
	if intent.Operation != "add" && intent.Operation != "retire" {
		if err := writeIntent(ctx, store, targets, snapshots, registries, intent); err != nil {
			return err
		}
	}
	if intent.Operation == "activate" && current != intent.Kid {
		if err := activationReady(registries, intent.Kid, state); err != nil {
			intent.Operation = "cancel"
			intent.PrivateVersion = pending
			intent.Replacement = current
			if err := replacementReady(registries, intent, state); err != nil {
				return operationError(intent, err)
			}
			if err := writeIntent(ctx, store, targets, snapshots, registries, intent); err != nil {
				return err
			}
			outcome = "activation no longer valid; cancelled pending key"
		} else if err := privateWrite(ctx, func(writeCtx context.Context) error { return store.Activate(writeCtx, selected, name, state, pending) }); err != nil {
			return operationError(intent, err)
		}
	}
	if intent.Operation == "cancel" {
		if err := cancelPending(ctx, out, store, selected, name, state, intent); err != nil {
			return operationError(intent, err)
		}
	}
	if intent.Operation == "retire" || intent.Operation == "cancel" {
		after, err := store.Private(ctx, selected, name)
		if err != nil {
			return operationError(intent, err)
		}
		err = retirementReady(registries, intent, after)
		after.Clear()
		if err != nil {
			return operationError(intent, err)
		}
		delete(callers, intent.Kid)
	}
	if intent.Operation != "add" {
		advance(highWater, intent.Kid)
	}
	if intent.Operation != "activate" {
		r := mergedRegistry(callers, highWater, intent)
		for i := range targets {
			if intent.Operation == "add" {
				r = mergedRegistry(callers, registries[i].HighWater, intent)
				sequence, _ := keySequence(intent.Kid)
				if registries[i].Intent == nil && registries[i].HighWater[intent.Caller+"."+intent.Cell] >= sequence {
					r.Intent = nil
				}
			}
			if intent.Operation == "retire" || intent.Operation == "cancel" {
				fresh, err := store.Private(ctx, selected, name)
				if err != nil {
					return operationError(intent, err)
				}
				err = retirementReady(registries, intent, fresh)
				fresh.Clear()
				if err != nil {
					return operationError(intent, err)
				}
			}
			if err := writeRegistry(ctx, store, targets[i], &snapshots[i], r); err != nil {
				return operationError(intent, err)
			}
			registries[i] = r
		}
	}
	advance(highWater, intent.Kid)
	for i := range registries {
		registries[i].HighWater = highWater
	}
	if err := clearIntent(ctx, store, targets, snapshots, registries); err != nil {
		return operationError(intent, err)
	}
	if (intent.Operation == "activate" || current == intent.Kid) && expiryStatus(callers[intent.Kid]) == "expired" {
		outcome += "; current key expired"
	}
	_, err = fmt.Fprintln(out, "recovered", intent.Operation, intent.Kid, intent.ID, outcome)
	return err
}

func sameIntent(a, b *Intent) bool {
	x, y := *a, *b
	if (x.Operation == "activate" || x.Operation == "retire") && y.Operation == "cancel" {
		x.PrivateVersion = y.PrivateVersion
		x.Operation, x.Replacement = "cancel", y.Replacement
	}
	if (y.Operation == "activate" || y.Operation == "retire") && x.Operation == "cancel" {
		y.PrivateVersion = x.PrivateVersion
		y.Operation, y.Replacement = "cancel", x.Replacement
	}
	return sameJSON(x, y)
}
