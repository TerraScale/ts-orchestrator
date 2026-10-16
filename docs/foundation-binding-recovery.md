# Foundation binding recovery boundary

Preserve the protected foundation object and its versions before investigating
a generation, intent-digest or creation-provenance rejection. Current source
fails closed; it does not implement an automatic legacy-journal migration.

Legacy plan-only digests do not prove the complete signed material, access and
startup intent. Missing birth evidence cannot be reconstructed from resource
names, tags, a matching SDK observation or a newly signed generation. Restore
the original authenticated journal history when it exists. A replacement grant
alone does not authorize a logical reference to an existing resource.

Any separately reviewed migration must preserve these boundaries:

1. Retain each original create operation, request digest, retry token, first
   attempt time, grant digest and generation. Never relabel old birth evidence
   as a new operation or synthesize it for an existing resource.
2. Keep the installation identity, root chain, existing exact GRU prerequisites
   and retained signed grant bytes. A replacement grant remains a distinct
   signed authority; it cannot adopt a resource discovered by name.
3. Preserve founder slot identities, consumed or pending launches, request
   hashes and the reserved bootstrap budget. A new grant generation cannot
   reset paid allocations or erase accepted provider requests.
4. Reauthenticate the protected conditional-write history and fresh SDK facts
   before resuming any material publication or paid operation. Unresolved
   accepted creates remain fenced until their original request is recovered.

The next diagnostic action is to inspect the non-secret foundation record's
generation, intent digest and original creation entries against retained signed
grant bytes. Do not edit the record, copy live IDs into it or launch replacements
to make the error disappear.
