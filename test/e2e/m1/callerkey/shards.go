package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"
)

type journeyCase struct {
	name string
	run  func(*journey)
}

func casePlan() []journeyCase {
	var plan []journeyCase
	addCase := func(name string, run func(*journey)) {
		plan = append(plan, journeyCase{name, run})
	}
	for _, operation := range []string{"first", "activate", "retire", "cancel"} {
		for _, field := range []string{"caller", "cell", "replacement caller", "replacement cell"} {
			addCase("intent/"+operation+"/"+field, func(j *journey) { j.intentMismatch(operation, field) })
		}
	}
	for _, stage := range []string{"current", "pending", "absent", "unreadable"} {
		addCase("payload/"+stage+"/mismatch", func(j *journey) { j.addPayload(stage, true) })
		if stage == "current" || stage == "pending" {
			addCase("payload/"+stage+"/matching", func(j *journey) { j.addPayload(stage, false) })
		}
	}
	addCase("capacity/admission", (*journey).capacityAdmission)
	for _, legacy := range []bool{false, true} {
		addCase(fmt.Sprintf("capacity/recovery/%t", legacy), func(j *journey) { j.capacityRecovery(legacy) })
	}
	for _, current := range []bool{false, true} {
		addCase(fmt.Sprintf("capacity/orphans/%t", current), func(j *journey) { j.orphanCapacity(current) })
	}
	for _, operation := range []string{"first", "add", "activate", "retire", "cancel"} {
		boundaries := []int{0, 1, 4}
		if operation == "first" || operation == "add" {
			boundaries = []int{0, 1, 7}
		}
		if operation == "cancel" {
			boundaries = []int{0, 1, 4, 5}
		}
		for _, original := range boundaries {
			for _, mode := range []string{"before", "uncertain", "crash", "hidden", "late"} {
				addCase(fmt.Sprintf("failures/%s/%d/%s", operation, original, mode), func(j *journey) { j.failures(operation, mode, original) })
			}
		}
	}
	for _, operation := range []string{"first", "add"} {
		for _, delay := range []time.Duration{0, 11 * time.Minute, 100 * 365 * 24 * time.Hour} {
			for _, ordering := range []string{"immediate", "after recover", "after another add", "during another add", "after retire attempt", "after replacement retirement"} {
				addCase(fmt.Sprintf("late/%s/%s/%s", operation, delay, ordering), func(j *journey) { j.lateCreations(operation, delay, ordering) })
			}
		}
	}
	for _, delay := range []time.Duration{0, 11 * time.Minute, 100 * 365 * 24 * time.Hour} {
		for _, winner := range []string{"ts-auth.sjc.1", "ts-auth.sjc.2"} {
			addCase(fmt.Sprintf("overlap/%s/%s", delay, winner), func(j *journey) { j.overlappingCreations(delay, winner) })
		}
	}
	addCase("safety", (*journey).safetyNet)
	for _, lifetime := range []time.Duration{24 * time.Hour, -time.Hour} {
		for _, mode := range []string{"before", "uncertain", "crash", "hidden", "late"} {
			addCase(fmt.Sprintf("expiry/%s/%s", lifetime, mode), func(j *journey) { j.expiredRecovery(lifetime, mode) })
		}
	}
	for _, retire := range []bool{false, true} {
		addCase(fmt.Sprintf("concurrent/%t", retire), func(j *journey) { j.concurrent(retire) })
	}
	addCase("lifecycle/50-rotations", (*journey).lifecycle)
	return plan
}

func selectedCases(args []string) ([]journeyCase, string, bool) {
	require(len(args) > 0 && (args[0] == "list" || args[0] == "run"), "usage: callerkey list [i n] | run binary [i n]")
	listing := args[0] == "list"
	args = args[1:]
	binary := ""
	if !listing {
		require(len(args) > 0, "run requires the overlay-built command path")
		var err error
		binary, err = filepath.Abs(args[0])
		must(err)
		args = args[1:]
	}
	index, total := 0, 1
	if len(args) != 0 {
		require(len(args) == 2, "shard requires zero-based index and total")
		var err error
		index, err = strconv.Atoi(args[0])
		must(err)
		total, err = strconv.Atoi(args[1])
		must(err)
	}
	plan := casePlan()
	require(total > 0 && total <= len(plan) && index >= 0 && index < total, "invalid or empty shard")
	seen := map[string]bool{}
	var selected []journeyCase
	for shard := 0; shard < total; shard++ {
		count := 0
		for i, c := range plan {
			if i%total != shard {
				continue
			}
			require(!seen[c.name], "duplicate case: "+c.name)
			seen[c.name] = true
			count++
			if shard == index {
				selected = append(selected, c)
			}
		}
		require(count > 0, "empty shard")
	}
	require(len(seen) == len(plan), "shard union differs from unsharded plan")
	return selected, binary, listing
}
