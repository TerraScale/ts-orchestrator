package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/callerkey"
)

func (j *journey) editRegistries(edit func(*callerkey.Registry)) {
	for _, cell := range []string{"fra", "gru", "sjc"} {
		value := j.store.values[cell+"-1-terrabase-callers"]
		if value == nil {
			continue
		}
		var registry callerkey.Registry
		must(json.Unmarshal(value.Current.Content, &registry))
		edit(&registry)
		value.Current.Content = encoded(registry)
	}
}

func (j *journey) intentMismatch(operation, field string) {
	j.failOriginal(operation, "crash", 1)
	j.editRegistries(func(r *callerkey.Registry) {
		if r.Intent == nil {
			return
		}
		switch field {
		case "caller":
			r.Intent.Caller = "edge"
		case "cell":
			r.Intent.Cell = "gru"
		case "replacement caller":
			r.Intent.Replacement = "edge.sjc.9"
		case "replacement cell":
			r.Intent.Replacement = "ts-auth.gru.9"
		}
	})
	value := j.store.values["fra-1-terrabase-callers"]
	var registry callerkey.Registry
	must(json.Unmarshal(value.Current.Content, &registry))
	registry.Callers = slices.DeleteFunc(registry.Callers, func(c callerkey.Caller) bool { return c.Kid == "ts-auth.sjc.1" })
	value.Current.Content = encoded(registry)
	before, reads := j.store.writes, j.store.privateReads
	out, err := j.run(j.targets, "recover")
	fragment := strings.Fields(field)[0]
	require(err != nil && strings.Contains(out, fragment) && strings.Contains(out, "region fra") && j.store.writes == before && j.store.privateReads == reads, fmt.Sprintf("%s %s intent was not refused before repair: %s", operation, field, out))
	j.store.cases++
}

func (j *journey) addPayload(stage string, mismatch bool) {
	boundary := 7
	operation := "first"
	if stage == "pending" {
		operation = "add"
	}
	mode := "crash"
	if stage == "absent" || stage == "unreadable" {
		mode = "before"
	}
	j.failOriginal(operation, mode, boundary)
	if stage == "unreadable" {
		j.store.hidden["sjc-1-ts-auth-terrabase-key"] = true
	}
	if mismatch {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		jwk := callerkey.JWK{Kty: "EC", Crv: "P-256", X: base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), Y: base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))}
		j.editRegistries(func(r *callerkey.Registry) {
			var c callerkey.Caller
			if r.Intent.Entry != nil {
				c = *r.Intent.Entry
			} else {
				for _, entry := range r.Callers {
					if entry.Kid == r.Intent.Kid {
						c = entry
					}
				}
			}
			c.JWK = jwk
			r.Intent.Entry = &c
		})
	}
	before := j.store.writes
	out, err := j.run(j.targets, "recover")
	if mismatch && (stage == "current" || stage == "pending") {
		require(err != nil && strings.Contains(out, "public payload differs") && strings.Contains(out, "region sjc") && j.store.writes == before, "readable private payload mismatch published or repaired: "+out)
	} else {
		require(err == nil, "forward add recovery refused: "+out)
		if stage == "absent" || stage == "unreadable" {
			require(strings.Contains(out, "private key not visible"), "invisible private key was not reported")
		}
		j.converged()
	}
	j.store.cases++
}

func (j *journey) fillRegistry(limit int, intent *callerkey.Intent) {
	private := j.store.values["sjc-1-ts-auth-terrabase-key"]
	var key map[string]any
	must(json.Unmarshal(private.Current.Content, &key))
	var registry callerkey.Registry
	must(json.Unmarshal(j.store.values["fra-1-terrabase-callers"].Current.Content, &registry))
	registry.Intent = intent
	template := registry.Callers[0]
	for n := 10; ; n++ {
		c := template
		c.Kid = "ts-auth.sjc." + strconv.Itoa(n)
		registry.Callers = append(registry.Callers, c)
		if len(encoded(registry)) > limit {
			registry.Callers = registry.Callers[:len(registry.Callers)-1]
			break
		}
	}
	last := &registry.Callers[len(registry.Callers)-1]
	last.Grants = slices.Clone(last.Grants)
	for n := 1; ; n++ {
		last.Grants = append(last.Grants, fmt.Sprintf("data:%026d", n+1000))
		if len(encoded(registry)) > limit {
			last.Grants = last.Grants[:len(last.Grants)-1]
			break
		}
	}
	last.Grants = last.Grants[:len(last.Grants)-1]
	registry.HighWater["op.a"] = 1
	padding := limit - len(encoded(registry))
	require(padding >= 0, "no space for exact-edge high-water padding")
	delete(registry.HighWater, "op.a")
	registry.HighWater["op."+strings.Repeat("a", padding+1)] = 1
	for _, c := range registry.Callers[2:] {
		key["kid"], key["metadata"] = c.Kid, c
		private.Versions = append(private.Versions, wireSnapshot{Snapshot: callerkey.Snapshot{ID: private.Current.ID, Version: int64(len(private.Versions) + 1)}, Content: encoded(key), Name: c.Kid})
		private.Pending = append(private.Pending, false)
		private.Deleting = append(private.Deleting, false)
		private.DeletionTimes = append(private.DeletionTimes, time.Time{})
	}
	j.editRegistries(func(r *callerkey.Registry) { *r = registry })
	require(len(encoded(registry)) == limit, "registry was not filled to exact edge")
}

func (j *journey) capacityAdmission() {
	j.seed("retire")
	j.fillRegistry(14*1024, nil)
	before := j.store.writes
	out, err := j.run(j.targets, add("ts-auth.sjc.100")...)
	require(err != nil && strings.Contains(out, "registry capacity") && strings.Contains(out, "region fra") && j.store.writes == before, "capacity was not refused before intent: "+out)
	j.store.cases++
}

func (j *journey) capacityRecovery(legacy bool) {
	j.seed("retire")
	next := "ts-auth.sjc.101"
	if legacy {
		next = "ts-auth.sjc.1000000000000000001"
		var r callerkey.Registry
		must(json.Unmarshal(j.store.values["fra-1-terrabase-callers"].Current.Content, &r))
		entry := r.Callers[0]
		entry.Kid = "ts-auth.sjc.1000000000000000000"
		intent := &callerkey.Intent{ID: strings.Repeat("a", 32), Operation: "add", Kid: entry.Kid, Caller: "ts-auth", Cell: "sjc", Entry: &entry}
		j.fillRegistry(16*1024, intent)
		must(json.Unmarshal(j.store.values["fra-1-terrabase-callers"].Current.Content, &r))
		r.Callers = append(r.Callers, entry)
		require(len(encoded(r)) > 16*1024, "legacy fixture does not reproduce oversized publication")
	} else {
		j.fillRegistry(13*1024, nil)
		j.store.fail, j.store.mode = j.store.writes+1, "crash"
		_, err := j.run(j.targets, add("ts-auth.sjc.100")...)
		require(err != nil, "edge add did not interrupt")
		j.store.fail = 0
	}
	if legacy {
		snapshot := encoded(j.store.values)
		start := j.store.writes
		j.ok("recover")
		count := j.store.writes - start
		for boundary := 1; boundary <= count; boundary++ {
			j.reset()
			must(json.Unmarshal(snapshot, &j.store.values))
			j.store.fail, j.store.mode = boundary, "crash"
			_, err := j.run(j.targets, "recover")
			require(err != nil, "legacy recovery mutation did not interrupt")
			j.store.fail = 0
			j.recover()
			j.store.cases++
		}
	}
	j.recover()
	for j.converged() > 11*1024 {
		var r callerkey.Registry
		must(json.Unmarshal(j.store.values["fra-1-terrabase-callers"].Current.Content, &r))
		id := r.Callers[len(r.Callers)-1].Kid
		if id == "ts-auth.sjc.2" {
			id = r.Callers[len(r.Callers)-2].Kid
		}
		j.ok("retire", "--kid", id, "--replacement-kid", "ts-auth.sjc.2")
	}
	j.ok(add(next)...)
	j.ok("activate", "--kid", next)
	j.ok("retire", "--kid", "ts-auth.sjc.2", "--replacement-kid", next)
	j.converged()
	j.store.cases++
}

func (j *journey) orphanCapacity(current bool) {
	j.reset()
	if current {
		j.ok(add("ts-auth.sjc.1")...)
	}
	first := 1
	if current {
		first = 2
	}
	for n := first; n < first+8; n++ {
		j.store.fail, j.store.mode = j.store.writes+7, "before"
		_, err := j.run(j.targets, add("ts-auth.sjc."+strconv.Itoa(n))...)
		require(err != nil, "orphan add did not interrupt")
		j.store.fail = 0
		j.recover()
	}
	before := j.store.writes
	out, err := j.run(j.targets, add("ts-auth.sjc."+strconv.Itoa(first+8))...)
	require(err != nil && strings.Contains(out, "orphan limit 8") && strings.Contains(out, "retire orphan entries with a current replacement") && j.store.writes == before, "orphan bound was not enforced before writes: "+out)
	if current {
		j.ok("retire", "--kid", "ts-auth.sjc.2", "--replacement-kid", "ts-auth.sjc.1")
		j.ok(add("ts-auth.sjc.10")...)
		j.ok("activate", "--kid", "ts-auth.sjc.10")
		j.ok("retire", "--kid", "ts-auth.sjc.1", "--replacement-kid", "ts-auth.sjc.10")
		j.converged()
	}
	j.store.cases++
}
