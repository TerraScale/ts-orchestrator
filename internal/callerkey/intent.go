package callerkey

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

func validateIntent(intent *Intent, region string) error {
	mismatch := func(field string) error {
		return fmt.Errorf("intent %s mismatch in region %s for kid %s", field, region, intent.Kid)
	}
	parts := kidRE.FindStringSubmatch(intent.Kid)
	if len(parts) != 4 || intent.ID == "" || !slices.Contains([]string{"add", "activate", "retire", "cancel"}, intent.Operation) {
		return mismatch("operation or kid")
	}
	if intent.Caller != parts[1] {
		return mismatch("caller")
	}
	if intent.Cell != parts[2] {
		return mismatch("cell")
	}
	if intent.Replacement != "" {
		replacement := kidRE.FindStringSubmatch(intent.Replacement)
		if len(replacement) != 4 || replacement[1] != parts[1] || replacement[2] != parts[2] || intent.Replacement == intent.Kid {
			return mismatch("replacement kid")
		}
	} else if intent.Operation == "retire" || intent.Operation == "cancel" {
		return mismatch("replacement kid")
	}
	if intent.Entry != nil && (intent.Operation != "add" || intent.Entry.Kid != intent.Kid || intent.Entry.Caller != intent.Caller || validateCaller(*intent.Entry) != nil) {
		return mismatch("public entry")
	}
	return nil
}

func checkAddPayload(ctx context.Context, store Store, targets []Target, intent *Intent) error {
	if intent.Operation != "add" {
		return nil
	}
	if intent.Entry == nil {
		return errors.New("add intent has no valid public entry")
	}
	for _, target := range targets {
		if target.Cell != intent.Cell {
			continue
		}
		state, err := store.Private(ctx, target, secretName(intent.Caller, intent.Cell))
		defer state.Clear()
		if err != nil {
			return nil
		}
		versions := []Snapshot{state.Current}
		for _, version := range state.Versions {
			versions = append(versions, version.Snapshot)
		}
		for _, version := range versions {
			kid, err := privateKid(version)
			if err != nil {
				return err
			}
			if kid != intent.Kid {
				continue
			}
			public, err := publicFromPrivate(version)
			if err != nil || !sameJSON(public, *intent.Entry) {
				return fmt.Errorf("add intent public payload differs from private key %s in region %s", intent.Kid, target.Cell)
			}
		}
		return nil
	}
	return errors.New("operation region is not deployed")
}
