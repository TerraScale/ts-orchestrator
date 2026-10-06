// Package rolloutexec is the leader-run executor of internal/rollout. It
// turns a stored rollout record into effects and feeds what it observes back
// into the pure transition core:
//
//   - Executor is the loop. Only the authority leader drives it; every write
//     goes through rollout.Store, which fences it by the authority epoch, and
//     a new leader adopts the active rollout before it acts. A Program runs
//     the controller rollout (non-seed controllers first, the seed last and
//     alone) and only after it completes the host rollout (one seat of a
//     TerraBase partition at a time).
//   - Gate is checked before every unit step. ClusterGate holds a step until
//     the JetStream metadata group and every replicated stream are healthy
//     and would keep quorum while the unit restarts.
//   - HealthProof is the signed version/health proof a unit publishes on
//     protocol.RolloutProofSubject. Collector verifies proofs and is the only
//     source of the healthy, unhealthy and rollback-serving events.
//   - StepCommand is the leader-signed stage/activate request. KVDriver
//     posts it under the unit's key in the rollout bucket; the unit's
//     controller relays it (Relay) to the node's root step agent, the
//     self-update watchdog (ApplySpooled), and relays the reply back. Agent
//     runs next to a unit's release root: it stages a release the relay
//     fetched, activates it with internal/selfupdate and restarts the unit.
//   - Status is the read-only rollout status published on
//     protocol.RolloutStatusSubject. It is telemetry, never admission
//     evidence.
//
// Every executor entry point is off by default; see docs/continuous-delivery.md.
package rolloutexec
