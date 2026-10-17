package authority

// RuntimeIdentity exposes the protected lease's identity for independent root
// consumers; it does not acquire authority or follow a successor.
func (a *LeaseAdmission) RuntimeIdentity() (deploymentID, candidateID string) {
	if a == nil {
		return "", ""
	}
	return a.lease.DeploymentID, a.lease.CandidateID
}
