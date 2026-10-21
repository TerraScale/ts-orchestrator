# Frozen FIFO6 correction: ownership and lock proof

Review successor commit 6a90d9b9b53abac59e191b8796cd367db62f0c25, tree 0bcdc7a7fc87ad7817d67e0032b668710e49d1b7, parent794296cc141ecf873b21d354469d1bce50d36a18, diagnostic base13185dcc. Both794 and successor remain unexecuted until QA lease. Only accounts.go, server.go and new service_import_lifecycle_test.go changed. Original accounts_test.go diagnostic bytes, workload and assertions remain unchanged. Original and diagnostic FAIL receipts remain OPEN and unchanged. No passing credit or FIFO7 advancement is claimed.

## Ownership and registration invariants

1. Each reservation allocates an immutable handle for (importing Account pointer, exact serviceImport pointer, owning client pointer, SID). A per-handle mutex guards installed subscription and cancellation. Account.mu guards the import's current handle/SID and an account registry of all pending/installed handles, including imports hidden in refresh/reload's old map. Correctness never depends on CID or current a.ic.
2. Reservation checks the exact import is still in the current map and enters the registry before releasing Account.mu. Actual processSubEx insertion and leaf +1 run under the handle mutex. Cancellation takes that mutex outside Account.mu. If cancellation wins, later insertion sees canceled and does nothing. If insertion wins, cancellation waits for insert and leaf +1, then performs owner-directed UNSUB and leaf -1. Two cleanup callers serialize and cleanup is idempotent.
3. removeAll detaches the entire registry and a.ic under Account.mu, clears current reservations, releases Account.mu, cancels all captured handles, then closes the captured current client. This reclaims hidden imports and pending insertions. A concurrent new reservation uses a new handle/client/registry. Old cleanup deletes only its exact registry key and clears import metadata only if it still names that handle, so it cannot clear a successor reservation on the same import pointer.
4. Refresh and config reload snapshot exact old handles during map detachment. Delayed cleanup targets those handles, never current a.ic. Stale addAll snapshots are rejected by pointer identity. Error unwind matches both exact import and exact reservation before map removal; it still cancels the old handle if a successor has replaced it. Config shallow copies clear runtime ownership fields rather than sharing a live registration.
5. Generic ACCOUNT admission, close sweeping, service-response subscriptions, auth-callout/stream reply subscriptions and queued publication behavior are unchanged. No blanket closed-internal rejection, new option, timeout change, workload reduction, sleep, drain or assertion change is used.

## Both failure schedules

Hidden old import: refresh removes I0 from current map while H0/C0/SID0 remains in the registry. Delete snapshots H0 even though I0 is hidden, cancels it and removes C0's actual subscription before closing C0. C1 can host a successor independently. Delayed refresh cleanup on H0 is idempotent and cannot remove or retain C1's registration.

Pending insertion: H0 enters the registry before processSubEx. Delete sees H0 even if SID0 is absent from C0.subs. It either cancels before insertion, or waits for completed insertion and leaf propagation before removing it. The same I may already name H1/C1/SID1 when H0's paused call resumes; H0's canceled state prevents closed-ACCOUNT insertion, and conditional metadata cleanup preserves H1. Single-import removal uses the same coordination.

## Completion and ACK semantics

The resolver callbacks remain synchronous before their own ACKs. New cancellation joins the relevant reservation's insertion and leaf propagation, and no new goroutine is introduced. removeAll returns after all its captured handles are canceled/removed. An internal application callback that already passed deliverMsg's open-sub check is not joined; this preserves existing message-in-flight semantics. The FIFO6 workers perform only claims updates, and the final service traffic starts after both workers and final delete/restore replies. Apply-error swallowing, concurrent newer-JWT loading and skipped/no-change callbacks retain the source review's documented limits.

## Lock order and recursive callers

Account.mu protects only reserve/snapshot/detach/conditional metadata changes. No handle mutex is acquired while Account.mu is held. A handle operation can take client/account/sublist/leaf locks, but processSubEx releases client.mu before addShadowSubscriptions takes account.mu, and processUnsub similarly releases client.mu before reverse-response/leaf operations. Registry deletion and conditional metadata clearing occur after releasing the handle mutex.

configureAccounts now releases Server.mu before waiting for cancellation or addAll, and reacquires it after registerSystemImports. Startup already explicitly dropped server/account locks before addAll. This removes reload's Server.mu-to-handle wait edge. removeCb and deleted-account reload already call removeAll outside their server/account locks. Generic internal publishing can retain Server.mu then Account.mu but does not take service handle mutexes.

The existing cmu release around lookupAccount/import resolution remains unchanged. No handle mutex spans account resolution, validation, recursive claim application or destination-account lookup. Post-build cleanup can hold cmu then a handle, but handle insertion does not acquire cmu or resolve claims. Existing reverse-response cleanup manipulates response maps and queues messages; it does not apply/resolve account claims or acquire cmu. A per-handle lock does not serialize unrelated imports or introduce a new account-wide reentrant lock.

Leaf +1 and owner UNSUB's leaf -1 share the handle lifetime, preventing a late +1 after completed retirement. Route/gateway helpers already skip service-import subscriptions. The source review traced the connected add/remove/refresh/reload/fetch/internal-publish paths; independent static review is requested to verify these claims before runtime.

## Focused regression and bounded execution request

TestAccountServiceImportSubscriptionLifecycle contains five focused subtests using production reserve/subscribe/cancel methods. They test hidden installed owner deletion and C1 replacement with repeated old cleanup; canceled reserved C0 insertion with the same import re-reserved on C1; and single removal plus stale snapshot/error unwind preserving a successor. Assertions inspect actual client submap, account sublist, closed subscription and current registration identity. Assertions release held locks before fatal helpers.

request.json selects the lifecycle root, unchanged public FIFO6 root and two original reload roots exactly, once with -race, with the original build tags unchanged. Expected roots are four; the lifecycle root adds five subtests, totaling nine test identities. Requested resources: Short-A, pinned Go1.27.1, env -i/no GOROOT, nice19, GOMAXPROCS2, package/test parallelism1, Go timeout120s and outer180s. No test/build/lint has executed. Formatting used pinned gofmt only. Runtime requires explicit QA lease.

No shared feature mutation, push, cloud/host action or new agent occurred. The first metadata preparation attempt failed an argv-index preflight assertion before writing evidence files; its empty v1 directory is preserved. The v2 request was the first completed correction request; this v3 reduces its test/outer limits per QA without changing frozen source or its original fixture. Default vet remains enabled; no -vet override is added. Further race/equivalence/private/removal coverage remains separate and open.


## Successor correction and expanded regression boundary

QA approved unfreezing794 solely for the new failure-path data-race correction and requested leaf/error coverage. The error caller now passes _EMPTY_ as destination when the immutable expected handle is supplied. The removal helper checks current map/exact import/exact handle under Account.mu and derives expected.si.acc.Name while that lock remains held, before selecting/removing the import. Config reload remaps si.acc under the same account lock. si.from is immutable. The caller no longer reads the remappable si.acc outside the lock; stale handles are canceled without inspecting a successor destination.

The regression root now has five cases. The fourth invokes addServiceImport with a malformed local subject so the real processSubEx reaches Sublist.Insert, fails and returns ErrMalformedSubject; it checks that map entry, registration registry, client submap and account sublist are all empty afterward. This is an actual insertion-error path, not an injected error callback. The fifth starts a real loopback leaf listener and connected leaf server, locates the active import-account leaf connection and checks its svc interest tally through add, retirement, canceled late subscribe, successor registration, delayed old cleanup and single removal. The tally must be1,0,0,1,1,0 respectively. It exercises live leaf-accounting paths; it does not claim an exhaustive wire-level or all-topology qualification.

The proposed execution is now one targeted -race invocation selecting lifecycle, unchanged FIFO6, unchanged TestAccountReloadServiceImportPanic and unchanged TestConfigReloadAccountServicesImportExport. The reload panic test performs1000reloads with concurrent requests; the second exercises two-server route/service behavior before and after real reload. All selected original bodies remain byte-identical to diagnostic13185dcc; existing tags/default vet, env -i/no GOROOT, pinned Go1.27.1/nice19, p1/parallel1/GOMAXPROCS2, count1, Go120s/outer180s remain exact. There are four roots plus five lifecycle subcases=9expected test identities. No runtime has occurred, no lane acquired and no retries are authorized by this request alone.


Successor 2ef9b8b70826c4f8e0f3ae4e4ae2bc76d6a1158d adds only the leaf.smap initialization wait (2s bound/10ms interval), under leaf client.mu.RLock, before creating the import. Initialization holds the same lock throughout. Independent focused review accepted this correction; no runtime has run. Production ownership and error-destination argument is unchanged. Prior requests remain unused.

Packet v2 retains source and exact test workload; directory inventories close added/removed input-file gaps.
