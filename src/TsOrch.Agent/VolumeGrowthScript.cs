namespace TsOrch.Agent;

internal static partial class VolumeGrowthScript
{
    public const string PrivateMountVolumeScript = Prologue + "\n" + AliasFunctions + "\n" + SysfsFunctions + "\n" + MountChecks;

    private const string Prologue = """
        export LC_ALL=C
        resize_mode=$1
        mount_path=$2
        escaped_mp=$3
        expected_dev=$4
        expected_fs=$5
        stage_dir=$6
        parent_pid=$7
        expected_mount_id=$8
        disk_name=$9
        shift 9
        disk_mm=$1
        expected_disk_stat=$2
        expected_disk_by_id=$3
        part_name=$4
        part_mm=$5
        expected_part_stat=$6
        expected_stable_names=$7
        attached_dev=$8
        part_num=$9
        shift 9
        resize_tool=$1
        expected_mount_ino=$2
        agent_exe=$3
        agent_dll=$4
        disk_dev="/dev/$disk_name"
        part_dev="/dev/$part_name"
        staged_dev="$stage_dir/dev"
        staged_retired_dev="$stage_dir/retired-dev"
        staged_work="$stage_dir/tmp"
        staged_disk="$staged_dev/$disk_name"
        staged_part="$staged_dev/$part_name"
        parent_mountinfo="/proc/$parent_pid/mountinfo"
        expected_mp_stat="${expected_dev}|${expected_mount_ino}"
        sysfs_magic=62656572
        pinned_src=""
        alias_root=""
        fs_target="$stage_dir/fs-target"
        fs_target_mounted=0
        fs_target_id=""
        private_mp=$mount_path
        nl='
        '
        """;

    private const string MountChecks = """
        check_mount_visible() {
            cmv_snap=$1
            cmv_cur_id=$2
            cmv_cur_pid=$3
            cmv_cur_mp=$4
            cmv_visited=" $cmv_cur_id "
            cmv_blocked=0
            while IFS=" " read -r cmv_x_id cmv_x_pid _ _ cmv_x_mp _; do
                [ -n "$cmv_x_id" ] && [ -n "$cmv_x_mp" ] || continue
                if [ "$cmv_x_pid" = "$cmv_cur_id" ] && [ "$cmv_x_mp" = "$cmv_cur_mp" ]; then
                    cmv_blocked=1
                    break
                fi
            done < "$cmv_snap"
            if [ "$cmv_blocked" -ne 0 ]; then
                return 1
            fi
            while :; do
                cmv_p_found=0
                cmv_p_pid=""
                cmv_p_mp=""
                if [ "$cmv_cur_pid" != "$cmv_cur_id" ]; then
                    while IFS=" " read -r cmv_x_id cmv_x_pid _ _ cmv_x_mp _; do
                        [ -n "$cmv_x_id" ] && [ -n "$cmv_x_mp" ] || continue
                        if [ "$cmv_x_id" = "$cmv_cur_pid" ]; then
                            cmv_p_found=1
                            cmv_p_pid=$cmv_x_pid
                            cmv_p_mp=$cmv_x_mp
                            break
                        fi
                    done < "$cmv_snap"
                fi
                if [ "$cmv_p_found" -eq 0 ]; then
                    if [ "$cmv_cur_mp" != "/" ]; then
                        return 1
                    fi
                    cmv_blocked=0
                    while IFS=" " read -r cmv_x_id cmv_x_pid _ _ cmv_x_mp _; do
                        [ -n "$cmv_x_id" ] && [ -n "$cmv_x_mp" ] || continue
                        if [ "$cmv_x_id" != "$cmv_cur_id" ] && [ "$cmv_x_pid" = "$cmv_cur_pid" ] && [ "$cmv_x_mp" = "$cmv_cur_mp" ]; then
                            cmv_blocked=1
                            break
                        fi
                    done < "$cmv_snap"
                    if [ "$cmv_blocked" -ne 0 ]; then
                        return 1
                    fi
                    return 0
                fi
                case "$cmv_visited" in
                    *" $cmv_cur_pid "*) return 1 ;;
                esac
                cmv_visited="${cmv_visited}${cmv_cur_pid} "
                cmv_blocked=0
                while IFS=" " read -r cmv_x_id cmv_x_pid _ _ cmv_x_mp _; do
                    [ -n "$cmv_x_id" ] && [ -n "$cmv_x_mp" ] || continue
                    if [ "$cmv_x_pid" = "$cmv_cur_pid" ] && [ "$cmv_x_id" != "$cmv_cur_id" ]; then
                        if [ "$cmv_x_mp" = "/" ] || [ "$cmv_x_mp" = "$cmv_cur_mp" ]; then
                            cmv_blocked=1
                            break
                        fi
                        case "$cmv_cur_mp" in
                            "$cmv_x_mp"/*)
                                cmv_blocked=1
                                break
                                ;;
                        esac
                    fi
                done < "$cmv_snap"
                if [ "$cmv_blocked" -ne 0 ]; then
                    return 1
                fi
                cmv_cur_id=$cmv_cur_pid
                cmv_cur_pid=$cmv_p_pid
                cmv_cur_mp=$cmv_p_mp
            done
        }
        read_mountinfo() {
            mi_file=$1
            mi_match=${2:-$escaped_mp}
            mi_snap="$staged_work/mountinfo"
            top_count=0
            found_id=""
            found_mm=""
            found_root=""
            found_fs=""
            found_src=""
            found_ro=""
            if [ ! -r "$mi_file" ] || ! cat "$mi_file" > "$mi_snap" 2>/dev/null; then
                return 0
            fi
            while IFS=" " read -r mi_id mi_pid mi_mm mi_root mi_mp mi_rest; do
                if [ "$mi_mp" = "$mi_match" ]; then
                    if ! check_mount_visible "$mi_snap" "$mi_id" "$mi_pid" "$mi_mp"; then
                        continue
                    fi
                    top_count=$((top_count + 1))
                    found_id=$mi_id
                    found_mm=$mi_mm
                    found_root=$mi_root
                    found_ro=0
                    case ",${mi_rest%% *}," in
                        *,ro,*) found_ro=1 ;;
                    esac
                    after_sep=${mi_rest#* - }
                    if [ "$after_sep" != "$mi_rest" ]; then
                        found_fs=${after_sep%% *}
                        after_fs=${after_sep#* }
                        if [ "$after_fs" != "$after_sep" ]; then
                            found_src=${after_fs%% *}
                            after_src=${after_fs#* }
                            if [ "$after_src" != "$after_fs" ]; then
                                case ",${after_src%% *}," in
                                    *,ro,*) found_ro=1 ;;
                                esac
                            fi
                        else
                            found_src=""
                        fi
                    else
                        found_fs=""
                        found_src=""
                    fi
                fi
            done < "$mi_snap"
        }
        check_mount_dev() {
            phase=$1
            mp_parent=$(dirname -- "$mount_path")
            actual_stat=$(stat -c "%d|%i" "$private_mp" 2>/dev/null || true)
            parent_dev=$(stat -c "%d" "$(dirname -- "$private_mp")" 2>/dev/null || true)
            if [ ! -d "$private_mp" ] || [ -L "$private_mp" ] || [ "$actual_stat" != "$expected_mp_stat" ] || [ -z "$parent_dev" ] || [ "$parent_dev" = "$expected_dev" ]; then
                printf "%s\n" "Mount path $private_mp identity mismatch ($phase): expected $expected_mp_stat, found ${actual_stat:-none} (parent dev ${parent_dev:-none})." >&2
                exit 65
            fi
            parent_root_mp="/proc/$parent_pid/root$mount_path"
            parent_root_parent="/proc/$parent_pid/root$mp_parent"
            host_actual_stat=$(stat -c "%d|%i" "$parent_root_mp" 2>/dev/null || true)
            host_parent_dev=$(stat -c "%d" "$parent_root_parent" 2>/dev/null || true)
            if [ ! -d "$parent_root_mp" ] || [ -L "$parent_root_mp" ] || [ "$host_actual_stat" != "$expected_mp_stat" ] || [ -z "$host_parent_dev" ] || [ "$host_parent_dev" = "$expected_dev" ]; then
                printf "%s\n" "Host mount path $mount_path identity mismatch ($phase): expected $expected_mp_stat, found ${host_actual_stat:-none} (parent dev ${host_parent_dev:-none})." >&2
                exit 65
            fi
        }
        check_parent_disk() {
            parent_disk="$parent_root$disk_dev"
            parent_disk_stat=$(stat -c '%t|%T|%d|%i' -- "$parent_disk" 2>/dev/null || true)
            if [ -L "$parent_disk" ] || [ ! -b "$parent_disk" ] || [ "$parent_disk_stat" != "$expected_disk_stat" ]; then
                printf "%s\n" "Host block disk $disk_dev mismatch ($phase): expected $expected_disk_stat, found ${parent_disk_stat:-none}." >&2
                exit 65
            fi
        }
        check_parent_block_nodes() {
            phase=$1
            check_parent_disk
            cpbn_fd3=$(stat -L -c '%t|%T|%d|%i' /proc/self/fd/3 2>/dev/null || true)
            if [ ! -b /proc/self/fd/3 ] || [ "$cpbn_fd3" != "$parent_disk_stat" ]; then
                printf "%s\n" "Host block disk $disk_dev is not pinned fd 3 after verifying aliases ($phase): expected ${cpbn_fd3:-none}, found $parent_disk_stat." >&2
                exit 65
            fi
            if [ "$part_name" != "$disk_name" ]; then
                parent_part="$parent_root$part_dev"
                parent_part_stat=$(stat -c '%t|%T|%d|%i' -- "$parent_part" 2>/dev/null || true)
                cpbn_fd4=$(stat -L -c '%t|%T|%d|%i' /proc/self/fd/4 2>/dev/null || true)
                if [ -L "$parent_part" ] || [ ! -b "$parent_part" ] || [ "$parent_part_stat" != "$expected_part_stat" ] || [ ! -b /proc/self/fd/4 ] || [ "$cpbn_fd4" != "$parent_part_stat" ]; then
                    printf "%s\n" "Host block device $part_dev mismatch after verifying aliases ($phase): expected $expected_part_stat on pinned fd 4 (${cpbn_fd4:-none}), found ${parent_part_stat:-none}." >&2
                    exit 65
                fi
            fi
        }
        check_expected_oci() {
            case "$attached_dev" in
                "") ;;
                /dev/oracleoci/*)
                    case "${attached_dev#/dev/oracleoci/}" in
                        ""|.|..|*/*)
                            printf "%s\n" "Host OCI attachment $attached_dev is not a direct /dev/oracleoci alias ($phase)." >&2
                            exit 65
                            ;;
                    esac
                    if ! resolve_parent_path "$parent_root" "$attached_dev"; then
                        printf "%s\n" "Host OCI attachment $attached_dev could not be resolved in parent namespace ($phase)." >&2
                        exit 65
                    fi
                    if [ "$rpp_hops" -eq 0 ]; then
                        printf "%s\n" "Host OCI attachment $attached_dev is not a symlink in parent namespace ($phase)." >&2
                        exit 65
                    fi
                    parent_oci_target="$parent_root$rpp_resolved"
                    parent_oci_stat=$(stat -c '%t|%T|%d|%i' -- "$parent_oci_target" 2>/dev/null || true)
                    if [ "$rpp_resolved" != "$disk_dev" ] || [ -L "$parent_oci_target" ] || [ ! -b "$parent_oci_target" ] || [ "$parent_oci_stat" != "$expected_disk_stat" ]; then
                        printf "%s\n" "Host OCI attachment $attached_dev mismatch ($phase): expected $disk_dev ($expected_disk_stat), found ${rpp_resolved:-none} (${parent_oci_stat:-none})." >&2
                        exit 65
                    fi
                    ;;
                *)
                    printf "%s\n" "Host OCI attachment $attached_dev is not a /dev/oracleoci alias ($phase)." >&2
                    exit 65
                    ;;
            esac
        }
        check_parent_oci() {
            phase=$1
            parent_root="/proc/$parent_pid/root"
            parent_dev_dir="$parent_root/dev"
            parent_oci_dir="$parent_dev_dir/oracleoci"
            check_parent_disk
            check_expected_oci
            if ! dir_identity "$parent_dev_dir" || [ "$di_id" = absent ]; then
                printf "%s\n" "Host /dev is a symlink or not a directory ($phase)." >&2
                exit 65
            fi
            oci_dev_before=$di_id
            if ! dir_identity "$parent_oci_dir"; then
                printf "%s\n" "Host OCI directory /dev/oracleoci could not be scanned ($phase)." >&2
                exit 65
            fi
            oci_dir_before=$di_id
            if [ "$oci_dir_before" != absent ]; then
                scan_parent_oci
            elif [ -n "$attached_dev" ]; then
                printf "%s\n" "Host OCI directory /dev/oracleoci disappeared while $attached_dev is expected ($phase)." >&2
                exit 65
            fi
            check_expected_oci
            check_parent_disk
            dir_identity "$parent_dev_dir" || di_id=failed
            oci_dev_after=$di_id
            dir_identity "$parent_oci_dir" || di_id=failed
            if [ "$oci_dev_after" != "$oci_dev_before" ] || [ "$di_id" != "$oci_dir_before" ]; then
                printf "%s\n" "Host /dev or /dev/oracleoci changed while verifying $disk_dev ($phase)." >&2
                exit 65
            fi
        }
        classify_oci_entry() {
            coe_candidate="/dev/oracleoci/${des_entry##*/}"
            if [ -n "$attached_dev" ] && [ "$coe_candidate" = "$attached_dev" ]; then
                if [ "$seen_expected" -ne 0 ]; then
                    printf "%s\n" "Host OCI attachment $attached_dev was listed more than once ($phase)." >&2
                    return 65
                fi
                seen_expected=1
                if [ "$des_is_link" -ne 1 ] || [ "$des_res_path" != "$disk_dev" ] || ! entry_block "$des_res_info" || [ "$eb_sig" != "$expected_disk_stat" ]; then
                    printf "%s\n" "Host OCI attachment $attached_dev mismatch in captured /dev/oracleoci snapshot ($phase): expected $disk_dev ($expected_disk_stat), found ${des_res_path:-none}." >&2
                    return 65
                fi
                return 0
            fi
            if [ -z "$des_res_path" ]; then
                printf "%s\n" "Host OCI alias $coe_candidate could not be resolved while verifying $disk_dev ($phase)." >&2
                return 65
            fi
            if [ "$des_res_path" = "$disk_dev" ] || { entry_block "$des_res_info" && [ "$eb_rdev" = "$expected_disk_rdev" ]; }; then
                printf "%s\n" "Conflicting host OCI alias $coe_candidate resolves to $disk_dev alongside ${attached_dev:-confirmed alias absence} ($phase)." >&2
                return 65
            fi
        }
        scan_parent_oci() {
            oci_err_file="$staged_work/oci.err"
            if [ ! -x "$parent_oci_dir" ] || ! dir_listing_state "$parent_oci_dir" "$oci_err_file"; then
                printf "%s\n" "Host OCI directory /dev/oracleoci could not be scanned ($phase)." >&2
                exit 65
            fi
            oci_has=$dls_has
            expected_disk_rdev=${expected_disk_stat%|*|*}
            seen_expected=0
            oci_rc=0
            dir_entry_signature "$parent_root" "$parent_oci_dir" classify_oci_entry || oci_rc=$?
            if [ "$oci_rc" -eq 1 ]; then
                printf "%s\n" "Host OCI directory /dev/oracleoci could not be captured consistently ($phase)." >&2
            fi
            if [ "$oci_rc" -ne 0 ]; then
                exit 65
            fi
            oci_before=$des_sig
            if [ "$des_id" != "$oci_dir_before" ] || [ "$des_seen" != "$oci_has" ] || ! dir_listing_state "$parent_oci_dir" "$oci_err_file" || [ "$dls_has" != "$oci_has" ] \
                || ! dir_entry_signature "$parent_root" "$parent_oci_dir" || [ "$des_sig" != "$oci_before" ] \
                || ! dir_identity "$parent_oci_dir" || [ "$di_id" != "$oci_dir_before" ]; then
                printf "%s\n" "Host OCI directory /dev/oracleoci could not be enumerated consistently ($phase)." >&2
                exit 65
            fi
            rm -f "$oci_err_file"
            if [ -n "$attached_dev" ] && [ "$seen_expected" -ne 1 ]; then
                printf "%s\n" "Host OCI attachment $attached_dev was not listed in /dev/oracleoci ($phase)." >&2
                exit 65
            fi
        }
        check_parent_mountinfo() {
            phase=$1
            read_mountinfo "$parent_mountinfo"
            if [ "$top_count" -ne 1 ] || [ "$found_id" != "$expected_mount_id" ] || [ "$found_mm" != "$part_mm" ] || [ "$found_root" != "/" ] || [ "$found_fs" != "$expected_fs" ] || [ "$found_ro" != 0 ] || { [ -n "$pinned_src" ] && [ "$found_src" != "$pinned_src" ]; }; then
                printf "%s\n" "Host mount at $mount_path changed ($phase): expected id=$expected_mount_id root=/ $expected_fs ($part_mm) src=${pinned_src:-any} rw, found id=${found_id:-none} root=${found_root:-none} ${found_fs:-none} (${found_mm:-none}) src=${found_src:-none} ro=${found_ro:-none} count=$top_count." >&2
                exit 65
            fi
            check_mount_dev "$phase"
        }
        recheck_parent_dirs() {
            phase=$1
            alias_root=$parent_root
            if ! dir_identity "$parent_dev_dir" || [ "$di_id" != "$oci_dev_before" ] \
                || ! dir_identity "$parent_oci_dir" || [ "$di_id" != "$oci_dir_before" ] \
                || { [ "$oci_dir_before" != absent ] && { ! dir_entry_signature "$parent_root" "$parent_oci_dir" || [ "$des_sig" != "$oci_before" ] || [ "$des_id" != "$oci_dir_before" ]; }; }; then
                printf "%s\n" "Host /dev or /dev/oracleoci changed while verifying stable aliases of $disk_dev ($phase)." >&2
                exit 65
            fi
            recheck_alias_sets "$parent_root/dev" "$phase"
            if ! dir_identity "$parent_dev_dir" || [ "$di_id" != "$oci_dev_before" ] \
                || ! dir_identity "$parent_oci_dir" || [ "$di_id" != "$oci_dir_before" ] \
                || { [ "$oci_dir_before" != absent ] && { ! dir_entry_signature "$parent_root" "$parent_oci_dir" || [ "$des_sig" != "$oci_before" ] || [ "$des_id" != "$oci_dir_before" ]; }; } \
                || ! dir_identity "$parent_oci_dir" || [ "$di_id" != "$oci_dir_before" ]; then
                printf "%s\n" "Host /dev or /dev/oracleoci changed after verifying stable aliases of $disk_dev ($phase)." >&2
                exit 65
            fi
            alias_root=""
        }
        decode_mount_field() {
            dmf_out=""
            dmf_rest=$1
            while :; do
                case "$dmf_rest" in
                    *\\*)
                        dmf_out="${dmf_out}${dmf_rest%%\\*}"
                        dmf_rest=${dmf_rest#*\\}
                        case "$dmf_rest" in
                            040*) dmf_out="${dmf_out} "; dmf_rest=${dmf_rest#040} ;;
                            011*) dmf_out="${dmf_out}$(printf '\t')"; dmf_rest=${dmf_rest#011} ;;
                            012*|000*) return 1 ;;
                            134*) dmf_out="${dmf_out}\\"; dmf_rest=${dmf_rest#134} ;;
                            *) dmf_out="${dmf_out}\\" ;;
                        esac
                        ;;
                    *)
                        dmf_out="${dmf_out}${dmf_rest}"
                        return 0
                        ;;
                esac
            done
        }
        scan_device_mounts() {
            sdm_snap="$staged_work/device-mounts"
            sdm_count=0
            sdm_other=""
            if [ ! -r /proc/self/mountinfo ] || ! cat /proc/self/mountinfo > "$sdm_snap" 2>/dev/null; then
                printf "%s\n" "Reading private mountinfo for $part_dev failed ($1)." >&2
                exit 65
            fi
            while IFS=" " read -r _ _ sdm_mm _ sdm_mp sdm_rest; do
                sdm_src=""
                sdm_after=${sdm_rest#* - }
                if [ "$sdm_after" != "$sdm_rest" ]; then
                    sdm_src=${sdm_after#* }
                    sdm_src=${sdm_src%% *}
                fi
                if [ "$sdm_mm" != "$part_mm" ] && [ "$sdm_src" != "$pinned_src" ] && [ "$sdm_src" != "$part_dev" ]; then
                    continue
                fi
                sdm_count=$((sdm_count + 1))
                if [ "$sdm_mp" != "$fs_target" ] && [ -z "$sdm_other" ]; then
                    sdm_other=$sdm_mp
                fi
            done < "$sdm_snap"
        }
        check_sole_target() {
            scan_device_mounts "$1"
            read_mountinfo /proc/self/mountinfo "$fs_target"
            fs_target_stat=$(stat -c "%d|%i" "$fs_target" 2>/dev/null || true)
            if [ "$sdm_count" -ne 1 ] || [ -n "$sdm_other" ] || [ "$top_count" -ne 1 ] || [ "$found_id" != "$fs_target_id" ] || [ "$found_mm" != "$part_mm" ] || [ "$found_root" != "/" ] || [ "$found_fs" != "$expected_fs" ] || [ "$found_src" != "$pinned_src" ] || [ "$found_ro" != 0 ] || [ "$fs_target_stat" != "$expected_mp_stat" ]; then
                printf "%s\n" "Private target $fs_target is not the sole verified mount of $part_dev ($1): expected id=$fs_target_id root=/ $expected_fs ($part_mm) src=$pinned_src rw $expected_mp_stat, found id=${found_id:-none} root=${found_root:-none} ${found_fs:-none} (${found_mm:-none}) src=${found_src:-none} ro=${found_ro:-none} count=$top_count mounts=$sdm_count other=${sdm_other:-none} ${fs_target_stat:-none}." >&2
                exit 65
            fi
        }
        check_parent_mount() {
            phase=$1
            check_parent_mountinfo "$phase"
            check_parent_oci "$phase"
            check_parent_aliases "$phase"
            recheck_parent_dirs "$phase"
            check_parent_block_nodes "$phase"
            check_parent_mountinfo "$phase"
        }
        if [ ! -d "$stage_dir" ] || [ -L "$stage_dir" ]; then
            printf "%s\n" "Private mount stage directory $stage_dir is missing or a symlink." >&2
            exit 65
        fi
        stage_meta=$(stat -c '%u:%a' "$stage_dir" 2>/dev/null || true)
        expected_stage_meta="$(id -u):700"
        if [ "$stage_meta" != "$expected_stage_meta" ]; then
            printf "%s\n" "Private mount stage directory $stage_dir has unexpected owner or mode: ${stage_meta:-none}." >&2
            exit 65
        fi
        trap 'if [ "$fs_target_mounted" -eq 1 ]; then umount "$fs_target" || :; fi' EXIT
        mount -t tmpfs -o mode=0700,size=16m tmpfs "$stage_dir"
        mkdir -m 0700 "$staged_work"
        mkdir -m 0755 "$staged_dev"
        mount -t tmpfs -o mode=0755,size=16m tmpfs "$staged_dev"
        for pseudo in null zero urandom; do
            : > "$staged_dev/$pseudo"
            mount --bind "/dev/$pseudo" "$staged_dev/$pseudo"
        done
        if [ -c /dev/full ]; then
            : > "$staged_dev/full"
            mount --bind /dev/full "$staged_dev/full"
        fi
        ln -s /proc/self/fd "$staged_dev/fd"
        ln -s /proc/self/fd/0 "$staged_dev/stdin"
        ln -s /proc/self/fd/1 "$staged_dev/stdout"
        ln -s /proc/self/fd/2 "$staged_dev/stderr"
        if [ ! -b "$disk_dev" ] || [ -L "$disk_dev" ]; then
            printf "%s\n" "Block disk $disk_dev is missing or a symlink in private namespace." >&2
            exit 65
        fi
        : > "$staged_disk"
        mount --bind "$disk_dev" "$staged_disk"
        disk_actual_stat=$(stat -L -c '%t|%T|%d|%i' "$staged_disk" 2>/dev/null || true)
        if [ -L "$staged_disk" ] || [ ! -b "$staged_disk" ] || [ "$disk_actual_stat" != "$expected_disk_stat" ]; then
            printf "%s\n" "Block disk $disk_dev changed before open: expected $expected_disk_stat, found ${disk_actual_stat:-none}." >&2
            exit 65
        fi
        exec 3<"$staged_disk"
        if [ "$part_name" != "$disk_name" ]; then
            if [ ! -b "$part_dev" ] || [ -L "$part_dev" ]; then
                printf "%s\n" "Block device $part_dev is missing or a symlink in private namespace." >&2
                exit 65
            fi
            : > "$staged_part"
            mount --bind "$part_dev" "$staged_part"
            part_actual_stat=$(stat -L -c '%t|%T|%d|%i' "$staged_part" 2>/dev/null || true)
            if [ -L "$staged_part" ] || [ ! -b "$staged_part" ] || [ "$part_actual_stat" != "$expected_part_stat" ]; then
                printf "%s\n" "Block device $part_dev changed before open: expected $expected_part_stat, found ${part_actual_stat:-none}." >&2
                exit 65
            fi
            exec 4<"$staged_part"
        fi
        check_sysfs "after open"
        check_aliases "/dev" "after open"
        check_parent_mount "after open"
        parent_src=$found_src
        read_mountinfo /proc/self/mountinfo
        if [ "$top_count" -ne 1 ] || [ "$found_mm" != "$part_mm" ] || [ "$found_root" != "/" ] || [ "$found_fs" != "$expected_fs" ] || [ -z "$found_id" ] || [ "$found_src" != "$parent_src" ] || [ "$found_ro" != 0 ]; then
            printf "%s\n" "Mount at $mount_path changed in private namespace: expected root=/ $expected_fs ($part_mm) src=$parent_src rw, found root=${found_root:-none} ${found_fs:-none} (${found_mm:-none}) src=${found_src:-none} ro=${found_ro:-none} count=$top_count." >&2
            exit 65
        fi
        case "$found_src" in
            /dev/?*) ;;
            *)
                printf "%s\n" "Mount source for $mount_path is not a block device: ${found_src:-none}." >&2
                exit 65
                ;;
        esac
        pinned_src=$found_src
        if decode_mount_field "$found_src"; then
            case "$dmf_out" in
                /dev/?*)
                    src_rel=${dmf_out#/dev/}
                    case "/$src_rel/" in
                        *//*|*/./*|*/../*) ;;
                        *)
                            src_target="$staged_dev/$src_rel"
                            if [ ! -e "$src_target" ] && [ ! -L "$src_target" ]; then
                                src_parent=$(dirname -- "$src_target")
                                mkdir -p -- "$src_parent"
                                ln -s -- "/dev/$part_name" "$src_target"
                            fi
                            ;;
                    esac
                    ;;
            esac
        fi
        mount --move "$staged_dev" /dev
        export TMPDIR="$staged_work"
        rescan_path="/sys/dev/block/$disk_mm/device/rescan"
        rescan_class_path="/sys/class/block/$disk_name/device/rescan"
        check_sysfs "before rescan probe"
        rescan_probe "/sys/dev/block/$disk_mm"
        rescan_dev_state=$rp_state
        rescan_probe "/sys/class/block/$disk_name"
        if [ "$rp_state" != "$rescan_dev_state" ]; then
            printf "%s\n" "Rescan attribute presence for $disk_dev differs between $rescan_path ($rescan_dev_state) and $rescan_class_path ($rp_state)." >&2
            exit 65
        fi
        if [ "$rescan_dev_state" = present ]; then
            check_parent_mount "before rescan"
            check_sysfs "before rescan write"
            resolve_rescan_target "before rescan write"
            rescan_before=$(stat -c '%F|%d|%i' -- "$rescan_path" 2>/dev/null) || rescan_before=""
            rescan_class_before=$(stat -c '%F|%d|%i' -- "$rescan_class_path" 2>/dev/null) || rescan_class_before=""
            case "$rescan_before" in
                "regular file|"*) ;;
                *)
                    printf "%s\n" "Rescan attribute $rescan_path for $disk_dev is not a regular sysfs file: ${rescan_before:-none}." >&2
                    exit 65
                    ;;
            esac
            if [ "$rescan_class_before" != "$rescan_before" ]; then
                printf "%s\n" "Rescan attribute $rescan_class_path for $disk_dev is not $rescan_path: expected $rescan_before, found ${rescan_class_before:-none}." >&2
                exit 65
            fi
            rescan_dev=${rescan_before#*|}
            rescan_ino=${rescan_dev#*|}
            rescan_dev=${rescan_dev%%|*}
            require_sysfs_rescan
            check_rescan_target "before rescan write"
            check_parent_mount "before rescan write"
            if ! sysfs_tool --sysfs-rescan-write "$rescan_path" "$rescan_real" "$rescan_dev" "$rescan_ino"; then
                printf "%s\n" "Rescanning block disk $disk_dev failed." >&2
                exit 66
            fi
            check_rescan_target "after rescan write"
            check_sysfs "after rescan"
        fi
        if [ -n "$part_num" ]; then
            gp_out_file="$staged_work/growpart.out"
            gp_err_file="$staged_work/growpart.err"
            check_sysfs "before growpart"
            check_partition_number "before growpart"
            check_parent_mount "before growpart"
            set +e
            growpart "$disk_dev" "$part_num" 3<&- 4<&- >"$gp_out_file" 2>"$gp_err_file"
            gp_rc=$?
            set -e
            if [ "$gp_rc" -ne 0 ]; then
                gp_out=$(cat "$gp_out_file") || exit 66
                case "$gp_out" in
                    *NOCHANGE*) ;;
                    *)
                        gp_err=$(cat "$gp_err_file") || exit 66
                        if [ -z "$gp_err" ]; then
                            gp_err=$gp_out
                        fi
                        printf "%s\n" "growpart failed with $gp_rc: $gp_err" >&2
                        exit 66
                        ;;
                esac
            fi
            check_sysfs "after growpart"
        else
            check_sysfs "before $resize_tool"
            check_whole_disk "before $resize_tool"
        fi
        mkdir -m 0700 "$fs_target"
        mount --bind "$mount_path" "$fs_target"
        fs_target_mounted=1
        read_mountinfo /proc/self/mountinfo "$fs_target"
        fs_target_stat=$(stat -c "%d|%i" "$fs_target" 2>/dev/null || true)
        if [ "$top_count" -ne 1 ] || [ "$found_mm" != "$part_mm" ] || [ "$found_root" != "/" ] || [ "$found_fs" != "$expected_fs" ] || [ "$found_src" != "$pinned_src" ] || [ "$found_ro" != 0 ] || [ "$fs_target_stat" != "$expected_mp_stat" ]; then
            printf "%s\n" "Private target for $mount_path is not the verified mount: expected root=/ $expected_fs ($part_mm) src=$pinned_src rw $expected_mp_stat, found root=${found_root:-none} ${found_fs:-none} (${found_mm:-none}) src=${found_src:-none} ro=${found_ro:-none} count=$top_count ${fs_target_stat:-none}." >&2
            exit 65
        fi
        fs_target_id=$found_id
        detach_rounds=0
        scan_device_mounts "before $resize_tool"
        while [ -n "$sdm_other" ]; do
            detach_rounds=$((detach_rounds + 1))
            if [ "$detach_rounds" -gt 64 ] || ! decode_mount_field "$sdm_other" || ! umount -l "$dmf_out" 3<&- 4<&-; then
                printf "%s\n" "Detaching private mount $sdm_other of $part_dev ($part_mm) before $resize_tool failed." >&2
                exit 65
            fi
            scan_device_mounts "before $resize_tool"
        done
        private_mp=$fs_target
        check_sole_target "before $resize_tool"
        check_parent_mount "before $resize_tool"
        set +e
        if [ "$resize_mode" = "resize_device" ]; then
            "$resize_tool" "$part_dev" 3<&- 4<&-
        else
            "$resize_tool" "$fs_target" 3<&- 4<&-
        fi
        rs_rc=$?
        set -e
        if [ "$rs_rc" -ne 0 ]; then
            if [ "$rs_rc" -eq 65 ]; then
                exit 66
            fi
            exit "$rs_rc"
        fi
        mkdir -m 0700 "$staged_retired_dev"
        mount --move /dev "$staged_retired_dev"
        check_sysfs "after $resize_tool"
        check_aliases "/dev" "after $resize_tool"
        check_sole_target "after $resize_tool"
        check_parent_mount "after $resize_tool"
        stat -f -c "TS_ORCH_STATFS %b %S %a" "$fs_target"
        umount "$fs_target"
        fs_target_mounted=0
        """;
}
