source "$(dirname "$0")/common.sh"
source "$here/runtime.sh"
restore_runtime
lane="$(dirname "$bin")/oracle-regions"
begin "never-reached regions: manager down and VCN blocked"
sudo --preserve-env=PATH unshare --mount --net --propagation private "$lane" fallback "$bin" "$work/fleet"
end "region-fallback -> workers without their manager and a VCN-partitioned pair deliver over NetBird"
