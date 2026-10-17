package drainwire

import (
	"bytes"
	"slices"
)

func (r PoolReceipt) Clone() PoolReceipt {
	r.CellSpecWire = bytes.Clone(r.CellSpecWire)
	r.RootChainWire = bytes.Clone(r.RootChainWire)
	r.ClusterCAPEM = bytes.Clone(r.ClusterCAPEM)
	r.WorkerCertificate = bytes.Clone(r.WorkerCertificate)
	r.ManagerCertificates = cloneCertificates(r.ManagerCertificates)
	r.Tasks = slices.Clone(r.Tasks)
	r.Challenges = slices.Clone(r.Challenges)
	r.Holds = slices.Clone(r.Holds)
	for index := range r.Holds {
		r.Holds[index].CertificateChain = cloneCertificates(r.Holds[index].CertificateChain)
		r.Holds[index].Signature = bytes.Clone(r.Holds[index].Signature)
	}
	r.Stops = slices.Clone(r.Stops)
	for index := range r.Stops {
		r.Stops[index].CertificateChain = cloneCertificates(r.Stops[index].CertificateChain)
		r.Stops[index].Signature = bytes.Clone(r.Stops[index].Signature)
	}
	return r
}

func cloneCertificates(certificates [][]byte) [][]byte {
	copy := slices.Clone(certificates)
	for index := range copy {
		copy[index] = bytes.Clone(copy[index])
	}
	return copy
}
