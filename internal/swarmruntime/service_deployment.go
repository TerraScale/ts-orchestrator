package swarmruntime

import (
	"encoding/json/v2"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Deployment is the signed workflow identity and approved immutable image.
type Deployment struct {
	Repository string `json:"repository"`
	RunID      string `json:"runId"`
	RunAttempt uint64 `json:"runAttempt,omitzero"`
	Revision   string `json:"revision"`
	Image      string `json:"image"`
}

var deploymentRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)
var deploymentImage = regexp.MustCompile(`^ghcr\.io/terrascale/[a-z0-9][a-z0-9._-]{0,127}@sha256:[0-9a-f]{64}$`)

func (d *Deployment) Validate() error {
	if d == nil {
		return nil
	}
	run, err := strconv.ParseUint(d.RunID, 10, 64)
	if err != nil || run == 0 || d.Repository == "" || !deploymentRevision.MatchString(d.Revision) || !deploymentImage.MatchString(d.Image) {
		return errors.New("invalid deployment identity")
	}
	return nil
}

// ErrSupersededDeployment is an older run than the accepted floor: a newer
// run of the same repository already released this service, so the older
// release has nothing left to do.
var ErrSupersededDeployment = errors.New("deployment is superseded by a newer signed run")

// ErrSupersededDuringBake is a region's bake whose desired entry a newer
// release replaced before the verdict: the newer release owns the outcome.
var ErrSupersededDuringBake = errors.New("release superseded during bake")

// Accepts orders signed runs and attempts; an attempt cannot change its approval.
func (d *Deployment) Accepts(next *Deployment) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if err := d.Validate(); err != nil {
		return err
	}
	if d == nil || next == nil {
		return nil
	}
	floor, _ := strconv.ParseUint(d.RunID, 10, 64)
	run, _ := strconv.ParseUint(next.RunID, 10, 64)
	if next.Repository != d.Repository {
		return errors.New("deployment belongs to another repository")
	}
	if run < floor {
		return ErrSupersededDeployment
	}
	if run == floor && (next.RunAttempt < d.RunAttempt || next.Revision != d.Revision || next.RunAttempt == d.RunAttempt && *next != *d) {
		return errors.New("deployment changes an already approved run; release from a newer signed run")
	}
	return nil
}

// AcceptsReplacement also protects a run's serving or baking digest.
func (d *Deployment) AcceptsReplacement(next *Deployment, serving bool) error {
	if err := d.Accepts(next); err != nil {
		return err
	}
	if serving && d != nil && next != nil && d.RunID == next.RunID && d.Image != next.Image {
		return errors.New("deployment changes an already approved run; release from a newer signed run")
	}
	return nil
}

const (
	LabelDeployment      = "terrascale.deployment"
	LabelDeploymentFloor = "terrascale.deployment-floor"
)

func validateServiceDeployment(name string, deployment, floor *Deployment) error {
	for _, d := range []*Deployment{deployment, floor} {
		if err := d.Validate(); err != nil {
			return err
		}
		if d != nil && !strings.HasPrefix(d.Image, "ghcr.io/terrascale/"+name+"@") {
			return errors.New("deployment image does not belong to the service")
		}
	}
	if deployment != nil && (floor == nil || *deployment != *floor) {
		return errors.New("service signed authority differs from its accepted floor")
	}
	return nil
}

func serviceDeployment(name string, labels map[string]string) (deployment, floor *Deployment, err error) {
	for key, target := range map[string]**Deployment{LabelDeployment: &deployment, LabelDeploymentFloor: &floor} {
		if value, exists := labels[key]; exists {
			if err := json.Unmarshal([]byte(value), target, json.RejectUnknownMembers(true)); err != nil || *target == nil {
				return nil, nil, errors.New("invalid service deployment labels")
			}
		}
	}
	return deployment, floor, validateServiceDeployment(name, deployment, floor)
}

// admitServiceSpec applies the same authority order as mesh selection while
// leaving the service-version CAS intact. A newer floor only invalidates signed state.
func admitServiceSpec(labels map[string]string, next ServiceSpec) error {
	generation, rollbackOf, err := serviceGeneration(labels)
	if err != nil {
		return err
	}
	deployment, floor, err := serviceDeployment(next.Name, labels)
	if err != nil {
		return err
	}
	if floor != nil && next.DeploymentFloor == nil {
		return errors.New("service deployment floor cannot be removed")
	}
	if err := floor.AcceptsReplacement(next.DeploymentFloor, deployment != nil && rollbackOf == 0); err != nil {
		return err
	}
	if deployment != nil && next.DeploymentFloor != nil && *deployment != *next.DeploymentFloor {
		return nil
	}
	if next.Generation != 0 && ServiceGenerationAfter(generation, rollbackOf, next.Generation, next.RollbackOf) {
		return errors.New("service generation cannot move backward")
	}
	return nil
}
