package mesh

import (
	"errors"
	"regexp"
	"strconv"
)

// Deployment is the signed workflow identity and approved immutable image.
// It survives rollback and operator applies so an old run cannot regain authority.
type Deployment struct {
	Repository string `json:"repository"`
	RunID      string `json:"runId"`
	Revision   string `json:"revision"`
	Image      string `json:"image"`
}

var revision = regexp.MustCompile(`^[0-9a-f]{40}$`)

func validDeployment(d *Deployment) error {
	if d == nil {
		return nil
	}
	run, err := strconv.ParseUint(d.RunID, 10, 64)
	if err != nil || run == 0 || d.Repository == "" || !revision.MatchString(d.Revision) || !imageDigest.MatchString(d.Image) {
		return errors.New("invalid deployment identity")
	}
	return nil
}

var imageDigest = regexp.MustCompile(`^ghcr\.io/terrascale/[a-z0-9][a-z0-9._-]{0,127}@sha256:[0-9a-f]{64}$`)

func acceptsDeployment(current, next *Deployment) error {
	if err := validDeployment(next); err != nil {
		return err
	}
	if current == nil || next == nil {
		return nil
	}
	if err := validDeployment(current); err != nil {
		return err
	}
	floor, _ := strconv.ParseUint(current.RunID, 10, 64)
	run, _ := strconv.ParseUint(next.RunID, 10, 64)
	if next.Repository != current.Repository || run < floor || run == floor && *next != *current {
		return errors.New("deployment is stale or changes an already approved run")
	}
	return nil
}
