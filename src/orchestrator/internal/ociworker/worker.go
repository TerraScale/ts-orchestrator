// Package ociworker serializes the official SDK's metadata globals and its
// context-insensitive federation refresh paths across all host credential users.
package ociworker

// Gate is held until the SDK call exits, including after its caller cancels.
// Dispatchers must separately reject all calls after cancellation.
var Gate = make(chan struct{}, 1)
