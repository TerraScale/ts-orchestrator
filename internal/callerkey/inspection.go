package callerkey

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

type privateKey struct {
	Kid      string `json:"kid"`
	JWK      `json:",inline"`
	D        string `json:"d"`
	Metadata Caller `json:"metadata"`
}

func publicFromPrivate(snapshot Snapshot) (Caller, error) {
	var key privateKey
	if json.Unmarshal(snapshot.Value, &key) != nil || key.Kid != key.Metadata.Kid {
		return Caller{}, errors.New("private key has invalid caller metadata")
	}
	scalar, err := base64.RawURLEncoding.Strict().DecodeString(key.D)
	if err != nil {
		return Caller{}, errors.New("private key has invalid scalar")
	}
	defer clear(scalar)
	private, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		return Caller{}, errors.New("private key has invalid scalar")
	}
	point := private.PublicKey().Bytes()
	public := JWK{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(point[1:33]), Y: base64.RawURLEncoding.EncodeToString(point[33:])}
	if key.JWK != public || key.Metadata.JWK != public || validateCaller(key.Metadata) != nil {
		return Caller{}, errors.New("private key public half differs from caller metadata")
	}
	return key.Metadata, nil
}

func inspectCurrent(ctx context.Context, out io.Writer, store Store, targets []Target, snapshots []Snapshot, registries []Registry, callers map[string]Caller, repair bool) error {
	stages := map[string]string{}
	var violations []error
	for _, target := range targets {
		for _, service := range []string{"ts-auth", "dashboard", "edge"} {
			name := secretName(service, target.Cell)
			state, err := store.Private(ctx, target, name)
			if err != nil {
				if repair {
					violations = append(violations, fmt.Errorf("%s private key not visible; inspection unavailable", name))
					continue
				}
				return err
			}
			for _, version := range state.Versions {
				id, err := privateKid(version.Snapshot)
				if err != nil {
					state.Clear()
					return err
				}
				if version.Pending {
					stages[id] = "pending"
				} else if stages[id] == "" {
					stages[id] = "retained"
				}
			}
			if state.Current.Version == 0 {
				state.Clear()
				continue
			}
			public, err := publicFromPrivate(state.Current)
			state.Clear()
			if err != nil {
				return err
			}
			parts := kidRE.FindStringSubmatch(public.Kid)
			if len(parts) != 4 || parts[1] != service || parts[2] != target.Cell {
				return errors.New("current private key does not match its regional service")
			}
			stages[public.Kid] = "current"
			missing := []string{}
			for i := range targets {
				index := slices.IndexFunc(registries[i].Callers, func(c Caller) bool { return c.Kid == public.Kid && c.JWK == public.JWK })
				if index >= 0 {
					continue
				}
				missing = append(missing, targets[i].Cell)
				if repair {
					r := registries[i]
					r.Callers = slices.DeleteFunc(slices.Clone(r.Callers), func(c Caller) bool { return c.Kid == public.Kid })
					r.Callers = append(r.Callers, public)
					if r.HighWater == nil {
						r.HighWater = map[string]uint64{}
					}
					advance(r.HighWater, public.Kid)
					slices.SortFunc(r.Callers, func(a, b Caller) int { return strings.Compare(a.Kid, b.Kid) })
					if err := writeRegistry(ctx, store, targets[i], &snapshots[i], r); err != nil {
						return fmt.Errorf("repair interrupted: run recover: %w", err)
					}
					registries[i] = r
					callers[public.Kid] = public
					fmt.Fprintln(out, "repaired current key", public.Kid, "in region", targets[i].Cell)
				}
			}
			if len(missing) > 0 && !repair {
				err := fmt.Errorf("current key %s in region %s has no public entry in regions %s (missing or different public key)", public.Kid, target.Cell, strings.Join(missing, ", "))
				fmt.Fprintln(out, err)
				violations = append(violations, err)
			}
		}
	}
	if repair {
		return errors.Join(violations...)
	}
	for id, stage := range stages {
		if stage == "pending" {
			if _, ok := callers[id]; !ok {
				fmt.Fprintln(out, id, "pending without public entry; can only be cancelled")
			}
		}
	}
	for i, target := range targets {
		fmt.Fprintln(out, registryName(target), registryPresence(snapshots[i]))
		if intent := registries[i].Intent; intent != nil {
			fmt.Fprintln(out, "operation in progress", intent.Operation, intent.Kid, intent.ID, "run caller-key recover")
		}
		for _, caller := range registries[i].Callers {
			stage := stages[caller.Kid]
			if stage == "" {
				stage = "orphan (no private key visible)"
			}
			status := expiryStatus(caller)
			if stage == "pending" && !caller.NotAfter.After(time.Now().Add(minimumLifetime)) {
				status += "; can only be cancelled"
			}
			fmt.Fprintln(out, registryName(target), caller.Kid, stage, "notAfter", caller.NotAfter.UTC().Format(time.RFC3339), status)
		}
	}
	if len(violations) > 0 {
		return errors.New("current key registry invariant violated; run caller-key recover")
	}
	return nil
}
