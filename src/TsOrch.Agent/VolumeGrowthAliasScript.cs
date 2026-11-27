namespace TsOrch.Agent;

internal static partial class VolumeGrowthScript
{
    private const string AliasFunctions = """
        path_probe() {
            if pp_err=$(LC_ALL=C stat -- "$1" 2>&1 >/dev/null); then
                return 0
            fi
            case "$pp_err" in
                *": No such file or directory") return 1 ;;
            esac
            return 2
        }
        glob_kept() {
            if [ "$1" != "$2" ]; then
                return 0
            fi
            path_probe "$1"
        }
        probe_block() {
            pb_rdev=""
            pb_sig=""
            if ! pb_info=$(stat -c '%f %t %T %d %i' -- "$1"); then
                return 3
            fi
            case "$pb_info" in
                *[!0-9a-fA-F\ ]*|" "*|*" "|*"  "*|*" "*" "*" "*" "*" "*) return 4 ;;
                *" "*" "*" "*" "*) ;;
                *) return 4 ;;
            esac
            pb_mode=${pb_info%% *}
            if [ $(( 0x$pb_mode & 0xf000 )) -ne 24576 ]; then
                return 2
            fi
            pb_rest=${pb_info#* }
            pb_rdev=${pb_rest%% *}
            pb_rest=${pb_rest#* }
            pb_rdev="$pb_rdev|${pb_rest%% *}"
            pb_rest=${pb_rest#* }
            pb_sig="$pb_rdev|${pb_rest%% *}|${pb_rest#* }"
        }
        dir_identity() {
            if di_id=$(stat -c '%F|%d|%i' -- "$1" 2>/dev/null); then
                case "$di_id" in
                    "directory|"*) return 0 ;;
                esac
                return 2
            fi
            di_rc=0
            path_probe "$1" || di_rc=$?
            if [ "$di_rc" -ne 1 ]; then
                return 2
            fi
            di_id=absent
        }
        dir_listing_state() {
            if ! dls_out=$(ls -1 -A -- "$1/" 2>"$2" && printf x); then
                return 1
            fi
            dls_has=1
            if [ "$dls_out" = x ]; then
                dls_has=0
            fi
        }
        encode_alias_name() {
            en_rest=$1
            en_out=""
            while :; do
                case "$en_rest" in
                    *[%,]*)
                        en_head=${en_rest%%[%,]*}
                        en_rest=${en_rest#"$en_head"}
                        case "$en_rest" in
                            %*) en_out="$en_out$en_head%25" ;;
                            *) en_out="$en_out$en_head%2C" ;;
                        esac
                        en_rest=${en_rest#?}
                        ;;
                    *)
                        en_out="$en_out$en_rest"
                        return 0
                        ;;
                esac
            done
        }
        utf8_valid() {
            if ! uv_hex=$(printf '%s' "$1" | LC_ALL=C od -An -v -tx1 2>/dev/null); then
                return 1
            fi
            printf '%s\n' "$uv_hex" | awk '
                BEGIN { h = "0123456789abcdef"; need = 0; lo = 128; hi = 191; bad = 0 }
                {
                    for (i = 1; i <= NF; i++) {
                        b = (index(h, substr($i, 1, 1)) - 1) * 16 + index(h, substr($i, 2, 1)) - 1
                        if (need > 0) {
                            if (b < lo || b > hi) { bad = 1; exit }
                            need--; lo = 128; hi = 191; continue
                        }
                        if (b < 128) continue
                        if (b >= 194 && b <= 223) { need = 1; continue }
                        if (b == 224) { need = 2; lo = 160; continue }
                        if ((b >= 225 && b <= 236) || b == 238 || b == 239) { need = 2; continue }
                        if (b == 237) { need = 2; hi = 159; continue }
                        if (b == 240) { need = 3; lo = 144; continue }
                        if (b >= 241 && b <= 243) { need = 3; continue }
                        if (b == 244) { need = 3; hi = 143; continue }
                        bad = 1; exit
                    }
                }
                END { exit (bad || need > 0) ? 1 : 0 }'
        }
        entry_block() {
            eb_dev=${1%%:*}
            eb_rest=${1#*:}
            eb_ino=${eb_rest%%:*}
            eb_rest=${eb_rest#*:}
            eb_mode=${eb_rest%%:*}
            eb_rest=${eb_rest#*:}
            eb_rdev="${eb_rest%%:*}|${eb_rest#*:}"
            eb_sig="$eb_rdev|$eb_dev|$eb_ino"
            [ $(( 0x$eb_mode & 0xf000 )) -eq 24576 ]
        }
        dir_entry_signature() {
            des_root=$1
            des_dir=$2
            des_hook=${3-}
            des_sig="!"
            des_out=""
            des_text=""
            des_seen=0
            if ! dir_identity "$des_dir" || [ "$di_id" = absent ]; then
                return 1
            fi
            des_id=$di_id
            for des_kind in plain dot dotdot; do
                case "$des_kind" in
                    plain) des_pat="$des_dir/*"; set -- "$des_dir"/* ;;
                    dot) des_pat="$des_dir/.[!.]*"; set -- "$des_dir"/.[!.]* ;;
                    *) des_pat="$des_dir/..?*"; set -- "$des_dir"/..?* ;;
                esac
                for des_entry in "$@"; do
                    des_rc=0
                    glob_kept "$des_entry" "$des_pat" || des_rc=$?
                    if [ "$des_rc" -eq 1 ]; then
                        continue
                    fi
                    if [ "$des_rc" -ne 0 ]; then
                        return 1
                    fi
                    des_seen=1
                    if ! des_info=$(LC_ALL=C stat -c '%d:%i:%f:%t:%T' -- "$des_entry" 2>/dev/null); then
                        return 1
                    fi
                    case "$des_info" in
                        *[!0-9a-fA-F:]*|*:*:*:*:*:*|*::*|:*|*:) return 1 ;;
                        *:*:*:*:*) ;;
                        *) return 1 ;;
                    esac
                    des_target=-
                    des_resolved=-
                    des_is_link=0
                    des_res_path=${des_entry#"$des_root"}
                    des_res_info=$des_info
                    des_text="$des_text/${des_entry##*/}"
                    des_mode=${des_info#*:*:}
                    if [ $(( 0x${des_mode%%:*} & 0xf000 )) -eq 40960 ]; then
                        des_is_link=1
                        des_raw=$(readlink -- "$des_entry" 2>/dev/null && printf x) || return 1
                        des_raw=${des_raw%x}
                        case "$des_raw" in
                            ?*"$nl") ;;
                            *) return 1 ;;
                        esac
                        encode_alias_name "${des_raw%"$nl"}"
                        des_target=$en_out
                        des_resolved=dangling
                        des_res_path=""
                        des_res_info=""
                        if resolve_parent_path "$des_root" "${des_entry#"$des_root"}"; then
                            des_rinfo=$(LC_ALL=C stat -c '%d:%i:%f:%t:%T' -- "$des_root$rpp_resolved" 2>/dev/null) || return 1
                            case "$des_rinfo" in
                                *[!0-9a-fA-F:]*|*:*:*:*:*:*|*::*|:*|*:) return 1 ;;
                                *:*:*:*:*) ;;
                                *) return 1 ;;
                            esac
                            encode_alias_name "$rpp_resolved"
                            des_resolved="$en_out:$des_rinfo"
                            des_res_path=$rpp_resolved
                            des_res_info=$des_rinfo
                        elif [ "$rpp_missing" -ne 1 ]; then
                            return 1
                        fi
                        des_text="$des_text/${des_raw%"$nl"}$rpp_trail"
                    fi
                    encode_alias_name "${des_entry##*/}"
                    des_out="$des_out,$en_out,$des_info,$des_target,$des_resolved"
                    if [ -n "$des_hook" ]; then
                        "$des_hook" || return $?
                    fi
                done
            done
            if ! dir_listing_state "$des_dir" /dev/null || [ "$dls_has" != "$des_seen" ]; then
                return 1
            fi
            utf8_valid "$des_text" || return 1
            if ! dir_identity "$des_dir" || [ "$di_id" != "$des_id" ]; then
                return 1
            fi
            des_sig=$des_out
        }
        classify_alias_entry() {
            if [ -z "$des_res_path" ]; then
                printf "%s\n" "Alias entry $des_entry could not be resolved." >&2
                return 65
            fi
            if ! entry_block "$des_res_info" || [ "$eb_rdev" != "$sad_rdev" ]; then
                return 0
            fi
            if [ "$des_res_path" != "$dev_rel/$sad_target" ] || [ "$eb_sig" != "$sad_stat" ]; then
                printf "%s\n" "Conflicting alias entry $des_entry resolves to $des_res_path with the block numbers of $sad_target." >&2
                return 65
            fi
            cae_name=${des_entry##*/}
            case "$cae_name" in
                *"$nl"*)
                    printf "%s\n" "Stable device name $des_entry contains a newline and cannot be verified." >&2
                    return 65
                    ;;
            esac
            encode_alias_name "$cae_name"
            if ! printf '%s/%s\n' "$sad_sub" "$en_out" >> "$alias_file"; then
                return 65
            fi
            if [ "$sad_sub" = "by-id" ]; then
                ca_by_id=1
            fi
        }
        scan_alias_dir() {
            sad_dir=$1
            sad_sub=$2
            sad_target=$3
            sad_stat=$4
            sad_has=$5
            sad_rdev=${sad_stat%|*|*}
            if ! dir_identity "$sad_dir" || [ "$di_id" = absent ]; then
                printf "%s\n" "Alias directory $sad_dir is a symlink, not a directory, or could not be inspected." >&2
                return 65
            fi
            sad_id=$di_id
            sad_rc=0
            dir_entry_signature "$alias_root" "$sad_dir" classify_alias_entry || sad_rc=$?
            if [ "$sad_rc" -eq 1 ]; then
                printf "%s\n" "Alias directory $sad_dir could not be captured consistently." >&2
            fi
            if [ "$sad_rc" -ne 0 ]; then
                return 65
            fi
            sad_before=$des_sig
            if [ "$des_id" != "$sad_id" ] || [ "$des_seen" != "$sad_has" ] || ! dir_listing_state "$sad_dir" "$ls_err_file" || [ "$dls_has" != "$sad_has" ] \
                || ! dir_entry_signature "$alias_root" "$sad_dir" || [ "$des_sig" != "$sad_before" ] || [ "$des_id" != "$sad_id" ] \
                || ! dir_identity "$sad_dir" || [ "$di_id" != "$sad_id" ]; then
                printf "%s\n" "Alias directory $sad_dir could not be enumerated consistently." >&2
                return 65
            fi
        }
        alias_tree_state() {
            ats_root=$1
            shift
            ats_out=""
            for ats_rel in "" /disk "$@"; do
                case "$ats_rel" in
                    ""|/disk) ats_dir="$ats_root$ats_rel" ;;
                    *) ats_dir="$ats_root/disk/$ats_rel" ;;
                esac
                if ! dir_identity "$ats_dir"; then
                    printf "%s\n" "Alias directory $ats_dir is a symlink, not a directory, or could not be inspected." >&2
                    return 65
                fi
                ats_out="$ats_out $di_id"
            done
        }
        alias_dir_signatures() {
            ads_root=$1
            ads_absent=$2
            shift 2
            ads_out=""
            if [ "$ads_absent" -ne 0 ]; then
                return 0
            fi
            for ads_sub in "$@"; do
                if ! dir_identity "$ads_root/disk/$ads_sub"; then
                    return 1
                fi
                if [ "$di_id" = absent ]; then
                    ads_out="$ads_out/-"
                    continue
                fi
                ads_id=$di_id
                dir_entry_signature "$alias_root" "$ads_root/disk/$ads_sub" || return 1
                [ "$des_id" = "$ads_id" ] || return 1
                ads_out="$ads_out/$des_sig"
            done
        }
        collect_aliases() {
            dev_root=$1
            target_name=$2
            target_stat=$3
            shift 3
            ca_joined=""
            ca_by_id=0
            if [ -L "$dev_root" ] || [ ! -d "$dev_root" ]; then
                printf "%s\n" "Device root $dev_root is a symlink or not a directory." >&2
                return 65
            fi
            dev_rel=${dev_root#"$alias_root"}
            alias_tree_state "$dev_root" "$@" || return $?
            ca_before=$ats_out
            alias_file="$staged_work/aliases"
            sorted_file="$staged_work/aliases.sorted"
            ls_err_file="$staged_work/aliases.err"
            : > "$alias_file" || return 65
            ca_disk_absent=0
            ca_sigs=""
            if ! dir_listing_state "$dev_root/disk" "$ls_err_file"; then
                if [ -L "$dev_root/disk" ] || ! grep -Fq ": No such file or directory" "$ls_err_file"; then
                    rm -f "$ls_err_file"
                    printf "%s\n" "Alias root $dev_root/disk could not be scanned." >&2
                    return 65
                fi
                ca_disk_absent=1
            elif [ ! -x "$dev_root/disk" ]; then
                rm -f "$ls_err_file"
                printf "%s\n" "Alias root $dev_root/disk could not be scanned." >&2
                return 65
            fi
            if [ "$ca_disk_absent" -eq 0 ]; then
                for sub in "$@"; do
                    search_dir="$dev_root/disk/$sub"
                    if ! dir_listing_state "$search_dir" "$ls_err_file"; then
                        if [ ! -L "$search_dir" ] && grep -Fq ": No such file or directory" "$ls_err_file"; then
                            ca_sigs="$ca_sigs/-"
                            continue
                        fi
                        rm -f "$ls_err_file"
                        printf "%s\n" "Alias directory $search_dir could not be scanned." >&2
                        return 65
                    fi
                    if [ ! -x "$search_dir" ]; then
                        rm -f "$ls_err_file"
                        printf "%s\n" "Alias directory $search_dir could not be scanned." >&2
                        return 65
                    fi
                    scan_alias_dir "$search_dir" "$sub" "$target_name" "$target_stat" "$dls_has" || return $?
                    ca_sigs="$ca_sigs/$sad_before"
                done
            fi
            rm -f "$ls_err_file"
            alias_tree_state "$dev_root" "$@" || return $?
            if [ "$ats_out" != "$ca_before" ] || ! alias_dir_signatures "$dev_root" "$ca_disk_absent" "$@" || [ "$ads_out" != "$ca_sigs" ]; then
                printf "%s\n" "Alias directories under $dev_root/disk changed while collecting stable device names." >&2
                return 65
            fi
            alias_tree_state "$dev_root" "$@" || return $?
            if [ "$ats_out" != "$ca_before" ]; then
                printf "%s\n" "Alias directories under $dev_root/disk changed after collecting stable device names." >&2
                return 65
            fi
            ca_target="$dev_root/$target_name"
            ca_target_now=$(stat -c '%t|%T|%d|%i' -- "$ca_target" 2>/dev/null || true)
            if [ -L "$ca_target" ] || [ ! -b "$ca_target" ] || [ "$ca_target_now" != "$target_stat" ]; then
                printf "%s\n" "Block device $ca_target changed while collecting stable device names." >&2
                return 65
            fi
            LC_ALL=C sort "$alias_file" > "$sorted_file"
            ca_joined=$(paste -sd, - < "$sorted_file")
        }
        verify_alias_sets() {
            vas_root=$1
            vas_phase=$2
            vas_scope=$3
            collect_aliases "$vas_root" "$disk_name" "$expected_disk_stat" by-id
            actual_disk_by_id=$ca_joined
            disk_has_by_id=$ca_by_id
            vas_disk_tree=$ca_before
            vas_disk_absent=$ca_disk_absent
            vas_disk_sigs=$ca_sigs
            collect_aliases "$vas_root" "$part_name" "$expected_part_stat" by-id by-uuid
            actual_part_stable=$ca_joined
            part_has_by_id=$ca_by_id
            vas_part_tree=$ca_before
            vas_part_absent=$ca_disk_absent
            vas_part_sigs=$ca_sigs
            if [ "$disk_has_by_id" != "1" ]; then
                printf "%s\n" "$vas_scope disk $disk_dev has no verified by-id identity ($vas_phase)." >&2
                exit 65
            fi
            if [ "$part_has_by_id" != "1" ]; then
                printf "%s\n" "$vas_scope device $part_dev has no verified by-id identity ($vas_phase)." >&2
                exit 65
            fi
            if [ "$actual_disk_by_id" != "$expected_disk_by_id" ]; then
                printf "%s\n" "$vas_scope disk $disk_dev by-id identity mismatch ($vas_phase): expected [$expected_disk_by_id], found [$actual_disk_by_id]." >&2
                exit 65
            fi
            if [ "$actual_part_stable" != "$expected_stable_names" ]; then
                printf "%s\n" "$vas_scope device $part_dev stable identity mismatch ($vas_phase): expected [$expected_stable_names], found [$actual_part_stable]." >&2
                exit 65
            fi
        }
        recheck_alias_sets() {
            ras_root=$1
            ras_phase=$2
            if ! alias_tree_state "$ras_root" by-id || [ "$ats_out" != "$vas_disk_tree" ] \
                || ! alias_dir_signatures "$ras_root" "$vas_disk_absent" by-id || [ "$ads_out" != "$vas_disk_sigs" ] \
                || ! alias_tree_state "$ras_root" by-id by-uuid || [ "$ats_out" != "$vas_part_tree" ] \
                || ! alias_dir_signatures "$ras_root" "$vas_part_absent" by-id by-uuid || [ "$ads_out" != "$vas_part_sigs" ] \
                || ! alias_tree_state "$ras_root" by-id || [ "$ats_out" != "$vas_disk_tree" ] \
                || ! alias_tree_state "$ras_root" by-id by-uuid || [ "$ats_out" != "$vas_part_tree" ]; then
                printf "%s\n" "Stable alias directories under $ras_root/disk changed while verifying $disk_dev ($ras_phase)." >&2
                exit 65
            fi
        }
        check_parent_aliases() {
            phase=$1
            parent_root="/proc/$parent_pid/root"
            alias_root=$parent_root
            verify_alias_sets "$parent_root/dev" "$phase" "Host block"
            alias_root=""
        }
        check_aliases() {
            dev_root=$1
            phase=$2
            dev_real=$(readlink -f -- "$dev_root" 2>/dev/null || true)
            disk_live_stat=$(stat -L -c '%t|%T|%d|%i' "$dev_root/$disk_name" 2>/dev/null || true)
            if [ -z "$dev_real" ] || [ -L "$dev_root/$disk_name" ] || [ ! -b "$dev_root/$disk_name" ] || [ "$disk_live_stat" != "$expected_disk_stat" ]; then
                printf "%s\n" "Block disk $disk_dev node mismatch ($phase): expected $expected_disk_stat, found ${disk_live_stat:-none}." >&2
                exit 65
            fi
            if [ "$part_name" != "$disk_name" ]; then
                part_live_stat=$(stat -L -c '%t|%T|%d|%i' "$dev_root/$part_name" 2>/dev/null || true)
                if [ -L "$dev_root/$part_name" ] || [ ! -b "$dev_root/$part_name" ] || [ "$part_live_stat" != "$expected_part_stat" ]; then
                    printf "%s\n" "Block device $part_dev node mismatch ($phase): expected $expected_part_stat, found ${part_live_stat:-none}." >&2
                    exit 65
                fi
            fi
            alias_root=""
            verify_alias_sets "$dev_root" "$phase" "Block"
            if [ -n "$attached_dev" ]; then
                case "$attached_dev" in
                    /dev/*) attached_check="$dev_root${attached_dev#/dev}" ;;
                    *) attached_check="$attached_dev" ;;
                esac
                attached_rc=0
                attached_target=""
                pb_sig=""
                if resolve_parent_path "" "$attached_check" && [ "$rpp_hops" -ne 0 ] && utf8_valid "$rpp_trail"; then
                    attached_target=$rpp_resolved
                    probe_block "$attached_target" || attached_rc=$?
                else
                    attached_rc=1
                fi
                if [ "$attached_rc" -ne 0 ] || [ "$attached_target" != "$dev_root/$disk_name" ] || [ "$pb_sig" != "$expected_disk_stat" ]; then
                    printf "%s\n" "OCI attachment $attached_dev mismatch ($phase): expected $disk_dev ($expected_disk_stat), found ${attached_target:-none} (${pb_sig:-none})." >&2
                    exit 65
                fi
            fi
            recheck_alias_sets "$dev_root" "$phase"
        }
        resolve_parent_path() {
            rpp_root=$1
            rpp_rest=$2
            rpp_resolved=""
            rpp_hops=0
            rpp_cur=""
            rpp_missing=0
            rpp_trail=""
            case "$rpp_rest" in
                [/]*) rpp_rest=${rpp_rest#/} ;;
                *) return 1 ;;
            esac
            while [ -n "$rpp_rest" ]; do
                case "$rpp_rest" in
                    */*)
                        rpp_seg=${rpp_rest%%/*}
                        rpp_rest=${rpp_rest#*/}
                        rpp_more=1
                        ;;
                    *)
                        rpp_seg=$rpp_rest
                        rpp_rest=""
                        rpp_more=0
                        ;;
                esac
                case "$rpp_seg" in
                    ""|.)
                        continue
                        ;;
                    ..)
                        if [ -n "$rpp_cur" ]; then
                            if [ -L "$rpp_root$rpp_cur" ] || [ ! -d "$rpp_root$rpp_cur" ]; then
                                return 1
                            fi
                            rpp_cur=${rpp_cur%/*}
                        fi
                        continue
                        ;;
                esac
                rpp_next="$rpp_cur/$rpp_seg"
                if [ "$rpp_more" -eq 1 ]; then
                    if [ -L "$rpp_root$rpp_next" ] || [ ! -d "$rpp_root$rpp_next" ]; then
                        resolve_missing "$rpp_root$rpp_next"
                        return 1
                    fi
                    rpp_cur=$rpp_next
                    continue
                fi
                if [ -L "$rpp_root$rpp_next" ]; then
                    rpp_hops=$((rpp_hops + 1))
                    if [ "$rpp_hops" -gt 16 ]; then
                        return 1
                    fi
                    rpp_raw=$(readlink -- "$rpp_root$rpp_next" 2>/dev/null && printf x) || return 1
                    rpp_raw=${rpp_raw%x}
                    case "$rpp_raw" in
                        *"$nl") ;;
                        *) return 1 ;;
                    esac
                    rpp_target=${rpp_raw%"$nl"}
                    rpp_trail="$rpp_trail/$rpp_target"
                    case "$rpp_target" in
                        ""|*"$nl"*) return 1 ;;
                        [/]*)
                            rpp_cur=""
                            rpp_rest=${rpp_target#/}
                            ;;
                        *) rpp_rest=$rpp_target ;;
                    esac
                    continue
                fi
                if [ ! -e "$rpp_root$rpp_next" ]; then
                    resolve_missing "$rpp_root$rpp_next"
                    return 1
                fi
                rpp_resolved=$rpp_next
                return 0
            done
            return 1
        }
        resolve_missing() {
            rm_rc=0
            if [ ! -L "$1" ]; then
                path_probe "$1" || rm_rc=$?
            fi
            if [ "$rm_rc" -eq 1 ]; then
                rpp_missing=1
            fi
        }
        """;
}
