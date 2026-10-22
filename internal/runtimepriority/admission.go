package runtimepriority

import (
	"fmt"
	"strings"
	"time"
)

func validateReleaseQualification(q Object) {
	if !exact(q, "schema", "repository", "source_revision", "source_tree", "go_version", "go_mod_sha256", "go_sum_sha256", "verification", "artifacts") || str(q, "schema") != "terrascale.release.qualification.v1" || str(q, "repository") != "TerraScale/ts-orchestrator" || str(q, "go_version") != "go1.27.3" || !hashRE.MatchString(str(q, "go_mod_sha256")) || !hashRE.MatchString(str(q, "go_sum_sha256")) {
		fail("CI qualification is not a strict v1 two-binary manifest")
	}
	artifacts, ok := q["artifacts"].([]any)
	if !ok || len(artifacts) != 2 {
		fail("CI qualification requires the two ordered Linux binaries")
	}
	for i, arch := range []string{"amd64", "arm64"} {
		a := obj(artifacts[i], "qualified binary")
		if !exact(a, "architecture", "name", "bytes", "sha256") || str(a, "architecture") != arch || str(a, "name") != "terrascale-orchestrator-linux-"+arch || !hashRE.MatchString(str(a, "sha256")) {
			fail("CI qualification has an invalid or unordered binary")
		}
		if num(a["bytes"], "qualified binary bytes", 1) > 512<<20 {
			fail("CI qualification binary exceeds its size bound")
		}
	}
}
func requireMarker(log []byte, marker string) {
	count := 0
	for line := range strings.SplitSeq(string(log), "\n") {
		stamp, payload, ok := strings.Cut(strings.TrimSuffix(line, "\r"), " ")
		if !ok || payload != marker {
			continue
		}
		if _, e := time.Parse(time.RFC3339Nano, stamp); e != nil {
			fail("D15 producing job log marker has an invalid timestamp")
		}
		count++
	}
	if count != 1 {
		fail("D15 producing job log lacks one exact CI publication marker")
	}
}

type AdmissionPaths struct{ Probe, Publication, Qualification, RunDetail, JobLog, ReleaseTag string }

func AdmitProbe(paths AdmissionPaths) (receipt Object, err error) {
	defer recoverError(&err)
	d, dwire := load(paths.Publication, 16384)
	q, qwire := load(paths.Qualification, 65536)
	r, rwire := load(paths.RunDetail, 1<<20)
	log, _, e := readNoFollow(paths.JobLog, 32<<20)
	if e != nil {
		fail("cannot inspect D15 producing job log: %v", e)
	}
	probe, _, e := readNoFollow(paths.Probe, MaxProbeBytes)
	if e != nil {
		fail("cannot inspect D15 probe: %v", e)
	}
	validateReleaseQualification(q)
	if !exact(d, "schema", "repository", "source_revision", "source_tree", "verification", "probe") || str(d, "schema") != "terrascale.d15.probe-publication/v1" || str(d, "repository") != "TerraScale/ts-orchestrator" {
		fail("D15 probe publication descriptor has an unsupported schema")
	}
	source, tree := str(d, "source_revision"), str(d, "source_tree")
	if !gitRE.MatchString(source) || !gitRE.MatchString(tree) {
		fail("D15 probe descriptor lacks full source and tree identities")
	}
	v := sub(d, "verification")
	if !exact(v, "workflow", "job", "run_id", "run_number") || str(v, "workflow") != "ci.yml" || str(v, "job") != ProducerJob {
		fail("D15 probe descriptor lacks the exact CI producer")
	}
	runID, runNumber := num(v["run_id"], "probe run_id", 1), num(v["run_number"], "probe run_number", 1)
	if paths.ReleaseTag != fmt.Sprintf("ci-%s-run-%d", source, runID) {
		fail("D15 probe release tag differs from its source/run identity")
	}
	p := sub(d, "probe")
	if !exact(p, "name", "bytes", "sha256") || str(p, "name") != ProbeAsset {
		fail("D15 probe descriptor names an unsupported asset")
	}
	size := num(p["bytes"], "probe bytes", 1)
	hash := str(p, "sha256")
	if size > MaxProbeBytes || !hashRE.MatchString(hash) || int64(len(probe)) != size || Hash(probe) != hash {
		fail("downloaded D15 probe differs from the CI publication descriptor")
	}
	if q["repository"] != d["repository"] || str(q, "source_revision") != source || str(q, "source_tree") != tree {
		fail("CI qualification source differs from the D15 probe descriptor")
	}
	qv := sub(q, "verification")
	if !exact(qv, "workflow", "job", "run_id", "run_number", "conclusion") || str(qv, "workflow") != "ci.yml" || str(qv, "job") != ProducerJob || n(qv, "run_id") != runID || n(qv, "run_number") != runNumber || str(qv, "conclusion") != "success" {
		fail("CI qualification run differs from the D15 probe descriptor")
	}
	if !exact(r, "run_id", "run_number", "head_sha", "workflow", "status", "jobs") || n(r, "run_id") != runID || n(r, "run_number") != runNumber || str(r, "head_sha") != source || str(r, "workflow") != "ci.yml" || str(r, "status") != "success" {
		fail("live CI run readback is not successful for the D15 source")
	}
	jobs, ok := r["jobs"].([]any)
	if !ok || len(jobs) != 1 {
		fail("CI run readback lacks one exact D15-producing job")
	}
	job := obj(jobs[0], "D15-producing job")
	if str(job, "name") != ProducerJob {
		fail("CI run readback lacks one exact D15-producing job")
	}
	if !exact(job, "id", "run_id", "name", "status", "attempt") || n(job, "run_id") != runID || str(job, "status") != "success" {
		fail("D15-producing CI job is not successful for this run")
	}
	jobID, attempt := num(job["id"], "D15-producing job ID", 1), num(job["attempt"], "D15-producing job attempt", 1)
	requireMarker(log, fmt.Sprintf("TS_D15_PROBE_PUBLICATION_V1 source_sha=%s run_id=%d run_number=%d probe_sha256=%s descriptor_sha256=%s", source, runID, runNumber, hash, Hash(dwire)))
	requireMarker(log, fmt.Sprintf("TS_RELEASE_QUALIFICATION_V1 source_sha=%s run_id=%d run_number=%d manifest_sha256=%s", source, runID, runNumber, Hash(qwire)))
	receipt = Object{"schema": "terrascale.d15.probe-admission/v1", "repository": d["repository"], "source_revision": source, "source_tree": tree, "release_tag": paths.ReleaseTag, "run_id": runID, "run_number": runNumber, "workflow": "ci.yml", "job": ProducerJob, "job_id": jobID, "attempt": attempt, "probe_asset": ProbeAsset, "probe_bytes": size, "probe_sha256": hash, "publication_sha256": Hash(dwire), "qualification_sha256": Hash(qwire), "run_detail_sha256": Hash(rwire), "job_log_sha256": Hash(log)}
	return
}
