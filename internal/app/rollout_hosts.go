package app

// Host self-update on the authority leader: the host controller hands every
// host's "rollout" exchange to the rollout control (host.RolloutSink), which
// records the host's health proof, posts its step agent's reply to the step
// board and answers with the host's pending step, so host steps travel the
// same board as controller steps.
