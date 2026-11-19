# Apply staging service configuration

Staging's checked-in declarations define its auth origin, token audience and
object storage. An existing service retains its configuration on image releases.
Deploying the binary that embeds a changed declaration does not apply that
configuration to an existing service.

## Release prerequisites

Coordinate the declaration release with the application contract and staging
resources. Before applying, require the application images that support the
reviewed staging authority, email-off behavior and CDN identity contract. C7
must have provisioned every newly referenced secret in stg-vault, verified
staging-only access, and prepared the declared shapes bucket and CDN hostname.
The regional secret preflight must pass before publishing the orchestrator
binary that embeds those references.

The shapes bucket is `terrascale-stg-terrabase-shapes`; its CDN hostname is
`shapes-terrascale-stg-terrabase-shapes.terrascale.tech`. The credential names are
`stg-1-terrabase-shapes-access-key-id` and
`stg-1-terrabase-shapes-secret-access-key`. CDN zone and token bindings must
match the reviewed application contract before this configuration is applied.

Keep staging outside Development, with email off as derived by the application
from its isolated environment. Do not add SMTP or Cloudflare email credentials.
Do not apply staging declarations in a production mesh.

## Apply existing services while keeping their current images

Run this procedure as root on the staging manager, from a checkout containing
the reviewed declarations. It requires that manager's local Swarm control
socket and running staging mesh. An external diagnostic session cannot execute
it; arrange the existing authorized management path with C7. This procedure
does not install SSH keys or introduce an authentication endpoint.

Both `terrabase` and `ts-auth` must already exist. The commands prepare both
declarations before applying either one, reject a service outside `stg`, and
read each image from the service immediately before its apply. An absent
dashboard is created through the normal verified app-pull path after these
dependencies become ready.

```sh
(
  set -eu
  test "$(id -u)" = 0
  umask 077
  apply_directory=$(mktemp -d)
  trap 'rm -rf -- "$apply_directory"' EXIT
  ts-orch release preflight secrets
  for service in terrabase ts-auth; do
    jq -e --arg service "$service" '.name == $service and .regions == ["stg"]' "deploy/m1/services/stg/$service.json" >/dev/null
    ts-orch service inspect "$service" > "$apply_directory/$service-current.json"
    jq -e --arg service "$service" '.spec.name == $service and .spec.regions == ["stg"] and (.spec.image | type == "string" and length > 0)' "$apply_directory/$service-current.json" >/dev/null
    cp "deploy/m1/services/stg/$service.json" "$apply_directory/$service-reviewed.json"
  done
  for service in terrabase ts-auth; do
    ts-orch service inspect "$service" > "$apply_directory/$service-current.json"
    jq -e --arg service "$service" '.spec.name == $service and .spec.regions == ["stg"]' "$apply_directory/$service-current.json" >/dev/null
    current_image=$(jq -er '.spec.image | select(type == "string" and length > 0)' "$apply_directory/$service-current.json")
    jq --arg image "$current_image" '.image = $image' "$apply_directory/$service-reviewed.json" > "$apply_directory/$service-apply.json"
    ts-orch service apply -f "$apply_directory/$service-apply.json"
    ts-orch service inspect "$service" > "$apply_directory/$service-after.json"
    jq -e --arg image "$current_image" '.spec.image == $image and .spec.regions == ["stg"]' "$apply_directory/$service-after.json" >/dev/null
    ts-orch service ps "$service"
  done
  curl --fail --silent --show-error https://stg.api.terrascale.tech/readyz
  curl --fail --silent --show-error https://stg.auth.terrascale.tech/readyz
)
```

The apply order is TerraBase, then auth. A failed apply stops the procedure;
inspect the task error and fix its cause before another apply. Keep each
service's current verified image rather than substituting the digest in the
checked-in declaration. The normal image release path retains the applied
configuration afterward.

This is a deliberate configuration operation. The regular image rollout and
automatic bootstrap paths remain unchanged. See the
[general configuration procedure](regional-app-capacity.md#apply-a-deliberate-configuration-change)
and [staging bootstrap](../region-bootstrap.md#staging-region).
