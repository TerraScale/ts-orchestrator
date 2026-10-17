// Package roleconfig names the signed role-configuration wire contract.
package roleconfig

// Version rejects legacy configs rather than activating formerly disabled services.
// Version 2 requires freshly produced and signed switch-free desired state;
// readers never rewrite or re-sign historical configuration bytes.
const Version = 2
