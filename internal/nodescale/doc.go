// Package nodescale scales one region between 3 and 12 nodes on CPU, memory,
// disk and request load. The 3 quorum nodes are never removed. Decide is a
// pure function of the load samples, the node count and the last change; the
// regional leader samples every 30 seconds and acts on what it decides.
package nodescale
