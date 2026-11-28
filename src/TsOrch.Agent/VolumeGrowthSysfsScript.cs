namespace TsOrch.Agent;

internal static partial class VolumeGrowthScript
{
    private const string SysfsFunctions = $$"""
        mountinfo_fs() {
            mf_after=${1#* - }
            mf_fs=""
            if [ "$mf_after" != "$1" ]; then
                mf_fs=${mf_after%% *}
            fi
        }
        sysfs_mount_state() {
            sms_snap="$staged_work/sysfs-mountinfo"
            if ! cat /proc/self/mountinfo > "$sms_snap" 2>/dev/null; then
                printf "%s\n" "Mount table could not be read while verifying sysfs for $disk_dev ($1)." >&2
                exit 65
            fi
            sysfs_mount_id=""
            sms_count=0
            sms_cover=""
            while IFS=" " read -r sms_id sms_pid _ sms_root sms_mp sms_rest; do
                case "$sms_mp" in
                    /sys)
                        sms_count=$((sms_count + 1))
                        mountinfo_fs "$sms_rest"
                        if [ "$sms_root" = / ] && [ "$mf_fs" = sysfs ] && check_mount_visible "$sms_snap" "$sms_id" "$sms_pid" /sys; then
                            sysfs_mount_id=$sms_id
                        fi
                        ;;
                    {{MountTable.SysfsIndexMountPoints}})
                        sms_cover=$sms_mp
                        ;;
                esac
            done < "$sms_snap"
            if [ "$sms_count" -ne 1 ] || [ -z "$sysfs_mount_id" ] || [ -n "$sms_cover" ]; then
                rm -f -- "$sms_snap"
                printf "%s\n" "Sysfs for $disk_dev is not one uncovered /sys mount ($1): /sys mounts=$sms_count visible=${sysfs_mount_id:-none} submount=${sms_cover:-none}." >&2
                exit 65
            fi
            sysfs_device_cover "/sys/class/block/$disk_name" "$1"
            if [ "$part_name" != "$disk_name" ]; then
                sysfs_device_cover "/sys/class/block/$part_name" "$1"
            fi
            rm -f -- "$sms_snap"
        }
        sysfs_device_cover() {
            if ! sysfs_real_path "$1"; then
                rm -f -- "$sms_snap"
                printf "%s\n" "Sysfs device directory of $1 for $disk_dev does not resolve under /sys/devices ($2)." >&2
                exit 65
            fi
            sdc_real=$srp_out
            while IFS=" " read -r _ _ _ _ sdc_mp _; do
                case "$sdc_mp" in
                    /sys/*) ;;
                    *) continue ;;
                esac
                case "$sdc_real/" in
                    "$sdc_mp"/*) sms_cover=$sdc_mp ;;
                esac
                case "$sdc_mp" in
                    "$sdc_real"/*) sms_cover=$sdc_mp ;;
                esac
            done < "$sms_snap"
            if [ -n "$sms_cover" ]; then
                rm -f -- "$sms_snap"
                printf "%s\n" "Sysfs device directory $sdc_real for $disk_dev is covered by mount $sms_cover ($2)." >&2
                exit 65
            fi
        }
        sysfs_on_mount() {
            som_mnt=$(awk '$1 == "mnt_id:" { print $2 }' /proc/self/fdinfo/5 2>/dev/null 5<"$1" 3<&- 4<&-) || return 1
            [ -n "$som_mnt" ] && [ "$som_mnt" = "$sysfs_mount_id" ]
        }
        require_sysfs_mount() {
            rsm_phase=$1
            shift
            sysfs_mount_state "$rsm_phase"
            for rsm_path in "$@"; do
                if ! sysfs_on_mount "$rsm_path"; then
                    printf "%s\n" "Sysfs path $rsm_path for $disk_dev is not on the /sys mount $sysfs_mount_id ($rsm_phase)." >&2
                    exit 65
                fi
            done
        }
        sysfs_real_path() {
            srp_out=$(readlink -f -- "$1" 2>/dev/null) || return 1
            case "$srp_out" in
                /sys/devices/?*) ;;
                *) return 1 ;;
            esac
        }
        sysfs_tool() {
            if [ -n "$agent_dll" ]; then
                DOTNET_EnableDiagnostics=0 "$agent_exe" "$agent_dll" "$@" 3<&- 4<&-
            else
                DOTNET_EnableDiagnostics=0 "$agent_exe" "$@" 3<&- 4<&-
            fi
        }
        read_sysfs_attr() {
            rsa_val=""
            rsa_id=""
            sysfs_mount_state "reading $1"
            rsa_rc=0
            rsa_out=$(sysfs_tool --sysfs-read-attr "$1" 2>/dev/null) || rsa_rc=$?
            sysfs_mount_state "after reading $1"
            if [ "$rsa_rc" -eq 1 ]; then
                return 1
            fi
            if [ "$rsa_rc" -ne 0 ]; then
                return 2
            fi
            case "$rsa_out" in
                *"$nl"*|" "*|*" "*" "*) return 2 ;;
                ?*" "*) ;;
                *) return 2 ;;
            esac
            rsa_id=${rsa_out%% *}
            rsa_val=${rsa_out#* }
        }
        check_sysfs() {
            phase=$1
            fd3_now=$(stat -L -c '%t|%T|%d|%i' /proc/self/fd/3 2>/dev/null || true)
            if [ ! -b /proc/self/fd/3 ] || [ "$fd3_now" != "$expected_disk_stat" ]; then
                printf "%s\n" "Pinned block disk fd 3 mismatch ($phase): expected $expected_disk_stat, found ${fd3_now:-none}." >&2
                exit 65
            fi
            require_block_mounts "$phase"
            disk_sys=""
            disk_dev_block=""
            read_sysfs_attr "/sys/class/block/$disk_name/dev" && disk_sys=$rsa_val
            read_sysfs_attr "/sys/dev/block/$disk_mm/dev" && disk_dev_block=$rsa_val
            disk_sys_real=$(readlink -f -- "/sys/class/block/$disk_name" 2>/dev/null || true)
            disk_dev_block_real=$(readlink -f -- "/sys/dev/block/$disk_mm" 2>/dev/null || true)
            if [ "$disk_sys" != "$disk_mm" ] || [ "$disk_dev_block" != "$disk_mm" ] || [ -z "$disk_sys_real" ] || [ "$disk_dev_block_real" != "$disk_sys_real" ]; then
                printf "%s\n" "Block disk $disk_dev sysfs mismatch ($phase): expected $disk_mm, found class=${disk_sys:-none} devblock=${disk_dev_block:-none}." >&2
                exit 65
            fi
            if [ "$part_name" != "$disk_name" ]; then
                fd4_now=$(stat -L -c '%t|%T|%d|%i' /proc/self/fd/4 2>/dev/null || true)
                if [ ! -b /proc/self/fd/4 ] || [ "$fd4_now" != "$expected_part_stat" ]; then
                    printf "%s\n" "Pinned block device fd 4 mismatch ($phase): expected $expected_part_stat, found ${fd4_now:-none}." >&2
                    exit 65
                fi
                part_sys=""
                part_dev_block=""
                read_sysfs_attr "/sys/class/block/$part_name/dev" && part_sys=$rsa_val
                read_sysfs_attr "/sys/dev/block/$part_mm/dev" && part_dev_block=$rsa_val
                part_sys_real=$(readlink -f -- "/sys/class/block/$part_name" 2>/dev/null || true)
                part_dev_block_real=$(readlink -f -- "/sys/dev/block/$part_mm" 2>/dev/null || true)
                part_parent_real=$(dirname -- "$part_sys_real")
                if [ "$part_sys" != "$part_mm" ] || [ "$part_dev_block" != "$part_mm" ] || [ -z "$part_sys_real" ] || [ "$part_dev_block_real" != "$part_sys_real" ] || [ "$part_parent_real" != "$disk_sys_real" ]; then
                    printf "%s\n" "Block device $part_dev sysfs mismatch ($phase): expected $part_mm on $disk_name, found class=${part_sys:-none} devblock=${part_dev_block:-none}." >&2
                    exit 65
                fi
            fi
            require_block_mounts "$phase"
        }
        require_block_mounts() {
            if [ "$part_name" != "$disk_name" ]; then
                require_sysfs_mount "$1" "/sys/dev/block/$disk_mm/" "/sys/class/block/$disk_name/" "/sys/dev/block/$part_mm/" "/sys/class/block/$part_name/"
            else
                require_sysfs_mount "$1" "/sys/dev/block/$disk_mm/" "/sys/class/block/$disk_name/"
            fi
        }
        is_sysfs_path() {
            isp_type=$(stat -f -c '%t' -- "$1" 2>/dev/null) || return 1
            [ "$isp_type" = "$sysfs_magic" ]
        }
        require_sysfs_rescan() {
            for rsr_path in "$rescan_path" "$rescan_class_path" "/sys/dev/block/$disk_mm/" "/sys/dev/block/$disk_mm/device/" "/sys/class/block/$disk_name/" "/sys/class/block/$disk_name/device/"; do
                if ! is_sysfs_path "$rsr_path"; then
                    printf "%s\n" "Rescan path $rsr_path for $disk_dev is not on sysfs (filesystem type $sysfs_magic)." >&2
                    exit 65
                fi
            done
        }
        sysfs_dir_state() {
            if ! is_sysfs_path "$1/" || ! dir_identity "$1/" || [ "$di_id" = absent ]; then
                return 1
            fi
            sds_id=$di_id
            if ! dir_listing_state "$1" "$2" || ! is_sysfs_path "$1/" || ! dir_identity "$1/" || [ "$di_id" != "$sds_id" ]; then
                return 1
            fi
            case "$nl$dls_out" in
                *"$nl$3$nl"*) sds_entry=present ;;
                *) sds_entry=absent ;;
            esac
        }
        sysfs_entry_probe() {
            sep_err="$staged_work/rescan.err"
            if ! sysfs_dir_state "$1" "$sep_err" "$2"; then
                printf "%s\n" "Block sysfs directory $1 for $disk_dev is dangling, unreadable or not on sysfs before probing $2 for rescan." >&2
                exit 65
            fi
            sep_id=$sds_id
            sep_listed=$sds_entry
            sep_rc=0
            path_probe "$1/$2" || sep_rc=$?
            case "$sep_rc" in
                0) sep_state=present ;;
                1) sep_state=absent ;;
                *)
                    printf "%s\n" "Block sysfs entry $1/$2 for $disk_dev could not be probed before rescan." >&2
                    exit 65
                    ;;
            esac
            if ! sysfs_dir_state "$1" "$sep_err" "$2" || [ "$sds_id" != "$sep_id" ]; then
                printf "%s\n" "Block sysfs directory $1 for $disk_dev changed while probing $2 for rescan." >&2
                exit 65
            fi
            if [ "$sep_listed" != "$sep_state" ] || [ "$sds_entry" != "$sep_state" ]; then
                printf "%s\n" "Block sysfs listings of $1 for $disk_dev disagree with the $2 probe ($sep_state): listed before=$sep_listed after=$sds_entry." >&2
                exit 65
            fi
            rm -f "$sep_err"
        }
        rescan_probe() {
            sysfs_entry_probe "$1" device
            rp_base_id=$sep_id
            rp_state=$sep_state
            if [ "$rp_state" = absent ]; then
                return 0
            fi
            sysfs_entry_probe "$1/device" rescan
            rp_state=$sep_state
            if ! sysfs_dir_state "$1" "$sep_err" device || [ "$sds_id" != "$rp_base_id" ] || [ "$sds_entry" != present ]; then
                printf "%s\n" "Block sysfs directory $1 for $disk_dev changed while probing the rescan attribute." >&2
                exit 65
            fi
            rm -f "$sep_err"
        }
        require_rescan_mounts() {
            require_sysfs_mount "$1" "/sys/dev/block/$disk_mm/" "/sys/dev/block/$disk_mm/device/" "/sys/class/block/$disk_name/" "/sys/class/block/$disk_name/device/"
        }
        rescan_target_state() {
            rts_real=""
            rts_class_real=""
            rts_disk_real=""
            rts_class_disk_real=""
            sysfs_real_path "$rescan_path" && rts_real=$srp_out
            sysfs_real_path "$rescan_class_path" && rts_class_real=$srp_out
            sysfs_real_path "/sys/dev/block/$disk_mm" && rts_disk_real=$srp_out
            sysfs_real_path "/sys/class/block/$disk_name" && rts_class_disk_real=$srp_out
            case "$rts_real" in
                /sys/devices/?*/rescan) ;;
                *) return 1 ;;
            esac
            [ "$rts_class_real" = "$rts_real" ] && [ "$rts_disk_real" = "${rts_real%/rescan}/block/$disk_name" ] && [ "$rts_class_disk_real" = "$rts_disk_real" ]
        }
        resolve_rescan_target() {
            require_rescan_mounts "$1"
            if ! rescan_target_state; then
                printf "%s\n" "Rescan attribute of $disk_dev does not resolve beside its block directory ($1): rescan=${rts_real:-none} class=${rts_class_real:-none} block=${rts_disk_real:-none}." >&2
                exit 65
            fi
            rescan_real=$rts_real
            rescan_disk_real=$rts_disk_real
            require_rescan_mounts "$1"
        }
        check_rescan_target() {
            require_rescan_mounts "$1"
            crt_rescan=$(stat -c '%F|%d|%i' -- "$rescan_path" 2>/dev/null) || crt_rescan=""
            crt_class=$(stat -c '%F|%d|%i' -- "$rescan_class_path" 2>/dev/null) || crt_class=""
            if ! rescan_target_state || [ "$rts_real" != "$rescan_real" ] || [ "$rts_disk_real" != "$rescan_disk_real" ] \
                || [ "$crt_rescan" != "$rescan_before" ] || [ "$crt_class" != "$rescan_before" ]; then
                printf "%s\n" "Rescan attribute of $disk_dev is not $rescan_real ($1): found rescan=${rts_real:-none} block=${rts_disk_real:-none} identity=${crt_rescan:-none} class=${crt_class:-none}." >&2
                exit 65
            fi
            require_rescan_mounts "$1"
        }
        check_partition_number() {
            phase=$1
            cpn_dev=""
            cpn_class=""
            if [ "$part_name" != "$disk_name" ] && [ -n "$part_num" ] && read_sysfs_attr "/sys/dev/block/$part_mm/partition"; then
                cpn_dev=$rsa_val
                cpn_dev_id=$rsa_id
                if read_sysfs_attr "/sys/class/block/$part_name/partition" && [ "$rsa_id" = "$cpn_dev_id" ]; then
                    cpn_class=$rsa_val
                fi
            fi
            if [ "$part_name" = "$disk_name" ] || [ -z "$part_num" ] || [ "$cpn_dev" != "$part_num" ] || [ "$cpn_class" != "$part_num" ]; then
                printf "%s\n" "Partition number of $part_dev mismatch ($phase): expected $part_num, found devblock=${cpn_dev:-none} class=${cpn_class:-none}." >&2
                exit 65
            fi
        }
        check_whole_disk() {
            phase=$1
            if [ "$part_name" != "$disk_name" ] || [ "$part_mm" != "$disk_mm" ]; then
                printf "%s\n" "Block device $part_dev is not the whole disk $disk_dev ($phase)." >&2
                exit 65
            fi
            require_block_mounts "$phase"
            cwd_first=""
            cwd_err="$staged_work/whole-disk.err"
            for cwd_dir in "/sys/dev/block/$disk_mm" "/sys/class/block/$disk_name"; do
                if ! sysfs_dir_state "$cwd_dir" "$cwd_err" partition; then
                    printf "%s\n" "Block sysfs directory $cwd_dir for $disk_dev is dangling, unreadable or not on sysfs ($phase)." >&2
                    exit 65
                fi
                cwd_id=$sds_id
                if [ "$sds_entry" != absent ]; then
                    printf "%s\n" "Block sysfs directory $cwd_dir lists a partition attribute although $disk_dev is mounted as a whole disk ($phase)." >&2
                    exit 65
                fi
                cwd_dev=""
                cwd_dev_after=""
                read_sysfs_attr "$cwd_dir/dev" && cwd_dev=$rsa_val
                cwd_rc=0
                read_sysfs_attr "$cwd_dir/partition" || cwd_rc=$?
                read_sysfs_attr "$cwd_dir/dev" && cwd_dev_after=$rsa_val
                if [ "$cwd_dev" != "$disk_mm" ] || [ "$cwd_dev_after" != "$disk_mm" ]; then
                    printf "%s\n" "Block sysfs directory $cwd_dir is not $disk_dev ($phase): expected dev $disk_mm, found ${cwd_dev:-none} then ${cwd_dev_after:-none}." >&2
                    exit 65
                fi
                if [ "$cwd_rc" -ne 1 ] || ! sysfs_dir_state "$cwd_dir" "$cwd_err" partition || [ "$sds_id" != "$cwd_id" ] || [ "$sds_entry" != absent ] \
                    || { [ -n "$cwd_first" ] && [ "$cwd_id" != "$cwd_first" ]; }; then
                    printf "%s\n" "Block sysfs directory $cwd_dir for $disk_dev does not confirm partition absence ($phase)." >&2
                    exit 65
                fi
                cwd_first=$cwd_id
            done
            rm -f -- "$cwd_err"
            require_block_mounts "$phase"
        }
        """;
}
