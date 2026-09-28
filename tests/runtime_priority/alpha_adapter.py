#!/usr/bin/env python3
"""Pinned transport adapter for alpha D15 runtime-priority qualification."""

from __future__ import annotations

import copy
import datetime as dt
import hashlib
import http.client
import json
import os
import shlex
import signal
import ssl
import stat
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any

import pressure


MAX_REQUEST_BYTES = 1 << 20
MAX_REMOTE_OUTPUT_BYTES = 1 << 20
REMOTE_ACTIONS = r'''import copy,datetime as dt,hashlib,http.client,json,os,signal,stat,subprocess,sys,time
from pathlib import Path

req=json.load(sys.stdin)
transport=req["transport"]
runtime=transport["runtime"]
payload=req.get("remote_payload",{})

def emit(value):
    sys.stdout.write(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")

def run(argv,timeout=30,input_bytes=None,maximum=1048576):
    result=subprocess.run(argv,input=input_bytes,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                          timeout=timeout,check=False,env={"HOME":"/","LANG":"C","LC_ALL":"C",
                          "PATH":"/usr/bin:/bin"})
    if len(result.stdout)>maximum or len(result.stderr)>maximum:
        raise RuntimeError("remote command exceeded its output bound")
    if result.returncode:
        raise RuntimeError("pinned remote command failed")
    return result.stdout

def properties(unit,keys):
    argv=[runtime["systemctl_path"],"show","--no-pager"]
    for key in keys:
        argv.extend(["--property",key])
    argv.append(unit)
    raw=run(argv,timeout=20).decode("utf-8")
    values={}
    for line in raw.splitlines():
        key,sep,value=line.partition("=")
        if sep:
            values[key]=value
    return raw,values

def proc_stat_identity(raw):
    left=raw.find("("); right=raw.rfind(") ")
    if left<1 or right<=left:
        raise RuntimeError("malformed process stat")
    pid=int(raw[:left].strip()); fields=raw[right+2:].split()
    if len(fields)<20:
        raise RuntimeError("short process stat")
    return pid,fields[19]

def proc_cgroup_path(raw):
    rows=[line.split(":",2) for line in raw.splitlines()]
    unified=[row[2] for row in rows if len(row)==3 and row[0]=="0" and row[1]==""]
    if len(unified)!=1 or not unified[0].startswith("/") or ".." in Path(unified[0]).parts:
        raise RuntimeError("malformed unified process cgroup")
    return unified[0]

def process_witness(pid):
    root=Path("/proc")/str(pid)
    stat_raw=(root/"stat").read_text(encoding="utf-8")
    cgroup_raw=(root/"cgroup").read_text(encoding="utf-8")
    actual,_=proc_stat_identity(stat_raw)
    if actual!=pid:
        raise RuntimeError("process PID changed while reading its witness")
    return {"pid":pid,"stat_raw":stat_raw,"cgroup_raw":cgroup_raw,
            "host_boot_id":Path("/proc/sys/kernel/random/boot_id").read_text().strip()}

def oci_instance_metadata():
    fields={"instance_id":"id","image_id":"image","region":"regionInfo/regionIdentifier",
            "shape":"shape"}
    result={}
    for output,path in fields.items():
        connection=http.client.HTTPConnection("169.254.169.254",80,timeout=2)
        try:
            connection.request("GET","/opc/v2/instance/"+path,headers={
                "Authorization":"Bearer Oracle","Accept":"text/plain","Connection":"close"})
            response=connection.getresponse()
            if response.status!=200 or response.getheader("Content-Type","").split(";",1)[0] not in {"text/plain","application/json"}:
                raise RuntimeError("fixed OCI metadata v2 field did not return a plain value")
            if response.length is not None and response.length>4096:
                raise RuntimeError("OCI metadata v2 field exceeded its bound")
            raw=response.read(4097)
            if len(raw)>4096:
                raise RuntimeError("OCI metadata v2 field exceeded its bound")
            value=raw.decode("utf-8").strip()
            if response.getheader("Content-Type","").split(";",1)[0]=="application/json":
                value=json.loads(value)
            if not isinstance(value,str) or not value or "\n" in value or "\r" in value:
                raise RuntimeError("OCI metadata v2 omitted an allowlisted identity field")
            result[output]=value
        finally:
            connection.close()
    return result

def safe_cgroup(report_path):
    if not isinstance(report_path,str) or not report_path.startswith("/") or ".." in Path(report_path).parts:
        raise RuntimeError("unsafe reported cgroup")
    return safe_cgroup_absolute(Path("/sys/fs/cgroup")/report_path.lstrip("/"))

def safe_cgroup_absolute(path):
    root=Path("/sys/fs/cgroup").resolve(strict=True)
    if not path.is_absolute() or ".." in path.parts or path==root:
        raise RuntimeError("unsafe absolute cgroup path")
    if not path.is_dir() or path.is_symlink():
        raise RuntimeError("reported cgroup is unavailable")
    resolved=path.resolve(strict=True)
    if root not in resolved.parents:
        raise RuntimeError("reported cgroup resolves outside the cgroup root")
    return resolved

def native_role_cgroups(target,native_path,database_path):
    reported=safe_cgroup(target["cgroup"])
    native=safe_cgroup_absolute(Path(native_path))
    database=safe_cgroup_absolute(Path(database_path))
    role_path=reported.relative_to(native) if native in reported.parents else None
    if (reported!=database or role_path is None or len(role_path.parts)!=1 or
            target["kind"]!="terrabase"):
        raise RuntimeError("target is not the exact preflight native TerraBase role")
    return reported,native,database

def pressure_module():
    source=Path(runtime["stress_launcher_path"])
    data=source.read_bytes()
    digest=hashlib.sha256(data).hexdigest()
    if digest!=runtime["stress_launcher_sha256"]:
        raise RuntimeError("pinned pressure source hash differs on the target")
    info=source.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
        raise RuntimeError("pinned pressure source is not an immutable root-owned regular file")
    sys.path.insert(0,str(source.parent))
    import pressure
    return pressure,digest

def slice_path():
    pressure=req["pressure"]
    parent=Path(pressure["workload_cgroup"]["parent_path"]).resolve(strict=True)
    _raw,values=properties(runtime["workload_slice"],["ControlGroup","ActiveState"])
    if values.get("ActiveState")!="active" or "/sys/fs/cgroup"+values.get("ControlGroup","")!=str(parent):
        raise RuntimeError("configured workload slice differs from its exact live cgroup")
    return parent

def scope_unit():
    return "terrascale-d15-"+req["run_id"]+".scope"

def scope_props():
    return properties(scope_unit(),["ActiveState","ControlGroup","Slice","CPUQuotaPerSecUSec",
        "MemoryMax","MemoryMin","MemoryLow","IOWeight"])

def expected_scope_path():
    parent=slice_path()
    return parent/scope_unit()

def read_scope():
    raw,values=scope_props()
    unit=scope_unit(); parent=slice_path()
    control=values.get("ControlGroup","")
    path=Path("/sys/fs/cgroup")/control.lstrip("/")
    expected=parent/unit
    if control!="/"+str(expected.relative_to(Path("/sys/fs/cgroup"))) or values.get("Slice")!=runtime["workload_slice"]:
        raise RuntimeError("transient scope is outside the pinned slice or has a different unit path")
    return raw,values,path

def roles_from_state(state):
    roles={}
    rows=state.get("worker_roles")
    if type(rows) is not list:
        raise RuntimeError("worker state lacks role identities")
    for row in rows:
        if type(row) is not dict or set(row)!={"pid","role"}:
            raise RuntimeError("worker role record has an invalid shape")
        pid=row["pid"]; role=row["role"]
        if type(pid) is not int or pid<=1 or role not in {"cpu_worker","memory_worker","io_worker"} or pid in roles:
            raise RuntimeError("worker role record is invalid or repeated")
        roles[pid]=role
    return roles

def inventory(path,state,active):
    pressure,digest=pressure_module()
    if active:
        raw=(path/"cgroup.procs").read_text(encoding="ascii")
        pids=sorted(int(line) for line in raw.splitlines() if line)
        roles=roles_from_state(state)
        runners=[pid for pid in pids if pid not in roles]
        if len(runners)!=1:
            raise RuntimeError("pressure scope has an unknown or missing runner process")
        roles[runners[0]]="pressure_runner"
        current=pressure.pressure_cgroup_inventory(path,set(pids),roles)
    else:
        raw=""; pids=[]; current={"process_pids":[],"processes":[],"worker_process_pids":[],
            "cgroup_procs_raw":"","process_inventory_sha256":hashlib.sha256(b"[]").hexdigest()}
    return raw,pids,current,digest

def scope_values(path,values,active):
    pressure=req["pressure"]["workload_cgroup"]
    expected_cpu=pressure["cpu_max"]
    if active:
        cpu=(path/"cpu.max").read_text().strip()
        memory=(path/"memory.max").read_text().strip()
        memory_min=(path/"memory.min").read_text().strip()
        memory_low=(path/"memory.low").read_text().strip()
        io_weight=pressure_module()[0].cgroup_io_weight(path,pressure["io_device"])
    else:
        cpu=expected_cpu; memory=str(pressure["memory_max_bytes"])
        memory_min="0"; memory_low="0"; io_weight=pressure["io_weight"]
    if (cpu!=expected_cpu or memory!=str(pressure["memory_max_bytes"]) or
            memory_min!="0" or memory_low!="0" or io_weight!=pressure["io_weight"]):
        raise RuntimeError("effective transient scope cgroup limits differ from the request")
    return cpu,int(memory),int(io_weight)

def state_record():
    path=Path(req["pressure"]["io_directory"])/("terrascale-d15-"+req["run_id"])/"runner-status.json"
    info=path.stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o077 or info.st_size>16384:
        raise RuntimeError("pressure worker state is not a bounded private regular file")
    raw=path.read_text(encoding="utf-8")
    state=json.loads(raw)
    if state.get("run_id")!=req["run_id"] or state.get("schema")!="terrascale.d15.pressure-worker-state/v2":
        raise RuntimeError("pressure worker state is stale or mismatched")
    return path,raw,hashlib.sha256(raw.encode()).hexdigest(),state

def io_backing(pressure):
    module,_=pressure_module()
    return module.prove_block_backing(pressure["io_directory"])

def pressure_observation(require_active,completed=False):
    scope_raw,values,path=read_scope()
    active=values.get("ActiveState")=="active"
    if require_active and not active:
        raise RuntimeError("pressure transient scope exited before its configured duration")
    if completed and active:
        raise RuntimeError("pressure transient scope remained active after full duration")
    state_path,state_raw,state_digest,state=state_record()
    expected_status="COMPLETED" if completed else "RUNNING"
    if state.get("status")!=expected_status:
        raise RuntimeError("pressure worker state does not match the requested phase")
    present=path.is_dir()
    if active!=present:
        raise RuntimeError("scope active state and cgroup presence disagree")
    raw,pids,current,harness_digest=inventory(path,state,active)
    cpu,memory,weight=scope_values(path,values,active)
    backing=io_backing(req["pressure"])
    cgroup={"path":str(path),"parent_path":req["pressure"]["workload_cgroup"]["parent_path"],
        "cpu_max":cpu,"memory_max_bytes":memory,"memory_min_bytes":0,"memory_low_bytes":0,
        "io_weight":weight,"io_device":req["pressure"]["workload_cgroup"]["io_device"],
        "io_backing":backing,"scratch_directory":str(state_path.parent),
        "status_file_path":str(state_path),"worker_state_record":state_raw,
        "worker_state_sha256":state_digest,"systemd_scope":{"unit":scope_unit(),
        "slice":values.get("Slice"),"control_group":values.get("ControlGroup"),
        "parent_control_group":str(slice_path()).removeprefix("/sys/fs/cgroup"),
        "active_state":values.get("ActiveState"),"cgroup_present":present,
        "systemctl_show_raw":scope_raw},**current}
    return cgroup,harness_digest

def journal_records(after_cursor=None):
    pressure,_=pressure_module()
    argv=[runtime["journalctl_path"],"--kernel","--no-pager","--output=json","--lines=4096"]
    if after_cursor:
        argv.extend(["--after-cursor",after_cursor])
    raw=run(argv,timeout=20,maximum=1<<20).decode("utf-8")
    events=[]
    for line in raw.splitlines():
        if not line:
            continue
        digest=hashlib.sha256(line.encode()).hexdigest()
        try:
            parsed=pressure.parse_journal_record(line,expected_transport="kernel")
        except Exception:
            continue
        events.append({"source":"kernel","raw_record":line,"raw_record_sha256":digest,
                       "parsed":parsed})
    return events

def main():
    action=sys.argv[1]
    if action=="proc_witness":
        emit(process_witness(payload["pid"])); return
    if action=="uname":
        raw=run(["/usr/bin/uname","-m"],timeout=5).decode().strip(); emit({"architecture":raw}); return
    if action=="oci_metadata":
        emit({"oci_metadata":oci_instance_metadata()}); return
    if action=="service_state":
        guest_role=req["guest_role"]
        if guest_role not in {"host","controller"}:
            raise RuntimeError("service state has no pinned guest role")
        unit=runtime["service_names"][guest_role]
        raw,values=properties(unit,["ActiveState","MainPID","ControlGroup","NRestarts"])
        pid=int(values.get("MainPID","0"))
        if pid<=1:
            raise RuntimeError("service has no active main process")
        root=Path("/proc")/str(pid)
        emit({"guest_role":guest_role,"units":{unit:{"systemctl_show_raw":raw,
              "process_stat_raw":(root/"stat").read_text(),
              "process_cgroup_raw":(root/"cgroup").read_text()}},
              "host_boot_id":Path("/proc/sys/kernel/random/boot_id").read_text().strip()}); return
    if action=="qualify":
        import tempfile
        with tempfile.TemporaryDirectory(prefix="terrascale-d15-qualify-",dir="/run") as temporary:
            evidence=Path(temporary)/"evidence"
            guest_role=req["guest_role"]
            if guest_role not in {"host","controller"}:
                raise RuntimeError("qualifier has no pinned guest role")
            identity=req["identity"] if guest_role=="host" else req["controller_identity"]
            q=req["qualification"] if guest_role=="host" else req["controller_qualification"]
            argv=[runtime["remote_python_path"],runtime["qualify_path"],"qualify",
                  "--role",guest_role,
                  "--artifact-id",identity["artifact_id"],"--config-id",identity["config_id"],
                  "--image-id",identity["image_id"],
                  "--oci-instance-id",identity["oci_instance_id"],
                  "--profile-id",identity["profile_id"],
                  "--expected-system-slice-memory-min-bytes",str(q["expected_system_slice_memory_min_bytes"]),
                  "--expected-system-slice-memory-low-bytes",str(q["expected_system_slice_memory_low_bytes"]),
                  "--system-reserve-bytes",str(q["system_reserve_bytes"]),
                  "--allocatable-memory-bytes",str(q["allocatable_memory_bytes"]),
                  "--evidence-dir",str(evidence)]
            if guest_role=="host":
                argv.extend(["--expected-memory-min-bytes",str(q["expected_memory_min_bytes"]),
                             "--expected-memory-low-bytes",str(q["expected_memory_low_bytes"]),
                             "--database-pid",str(req["managed_process"]["pid"]),
                             "--database-memory-max-bytes",str(q["database_memory_max_bytes"])])
            else:
                argv.extend(["--expected-controller-memory-min-bytes",
                             str(q["expected_controller_memory_min_bytes"]),
                             "--expected-controller-memory-low-bytes",
                             str(q["expected_controller_memory_low_bytes"])])
            result=subprocess.run(argv,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                                  timeout=req["deadline_seconds"],check=False,
                                  env={"HOME":"/","LANG":"C","LC_ALL":"C","PATH":"/usr/bin:/bin"})
            if result.returncode:
                raise RuntimeError("packaged priority qualifier failed")
            summary_path=evidence/"summary.json"; log_path=evidence/"commands.log"
            summary_info=summary_path.stat(follow_symlinks=False)
            log_info=log_path.stat(follow_symlinks=False)
            if (not stat.S_ISREG(summary_info.st_mode) or summary_info.st_size>65536 or
                    not stat.S_ISREG(log_info.st_mode) or log_info.st_size>262144):
                raise RuntimeError("qualifier evidence is not bounded regular files")
            summary_raw=summary_path.read_bytes(); log_raw=log_path.read_bytes()
            if len(summary_raw)>65536 or len(log_raw)>262144:
                raise RuntimeError("qualifier evidence exceeded its bound")
            emit({"summary":json.loads(summary_raw),"commands_log":log_raw.decode("utf-8")}); return
    if action=="pressure_start":
        source=Path(runtime["stress_launcher_path"])
        actual_hash=hashlib.sha256(source.read_bytes()).hexdigest()
        if actual_hash!=runtime["stress_launcher_sha256"]:
            raise RuntimeError("target pressure worker source hash differs from the pin")
        if not stat.S_ISREG(source.stat(follow_symlinks=False).st_mode) or source.stat().st_uid!=0 or source.stat().st_mode&0o022:
            raise RuntimeError("pressure worker source must be immutable and root-owned")
        parent=slice_path()
        pressure=req["pressure"]
        unit=scope_unit(); expected=parent/unit
        quota,period=pressure["workload_cgroup"]["cpu_max"].split()
        pct=(int(quota)*100000)//int(period)
        percent=("%d.%03d"%(pct//1000,pct%1000)).rstrip("0").rstrip(".")
        manifest=copy.deepcopy(req["pressure_manifest"])
        manifest["pressure"]["workload_cgroup"]["path"]=str(expected)
        import tempfile
        fd,temp_name=tempfile.mkstemp(prefix="terrascale-d15-",suffix=".json",dir="/run")
        try:
            os.fchmod(fd,0o600)
            with os.fdopen(fd,"w") as stream:
                json.dump(manifest,stream,sort_keys=True,separators=(",",":")); stream.flush(); os.fsync(stream.fileno())
            workload=pressure["workload_cgroup"]
            argv=[runtime["systemd_run_path"],"--scope","--no-block","--quiet","--unit",unit,
                  "--slice",runtime["workload_slice"],"--property=CPUQuota="+percent+"%",
                  "--property=MemoryMax="+str(workload["memory_max_bytes"]),
                  "--property=MemoryMin=0","--property=MemoryLow=0",
                  "--property=IOWeight="+str(workload["io_weight"]),
                  runtime["remote_python_path"],runtime["stress_launcher_path"],"stress-worker",
                  "--manifest",temp_name,"--expected-native-runner-cgroup",req["native_runner_cgroup_path"],
                  "--protected-database-cgroup",req["protected_database_cgroup_path"],
                  "--assigned-pressure-cgroup",str(expected),"--run-id",req["run_id"],"--retain-evidence"]
            run(argv,timeout=20,maximum=65536)
            deadline=time.monotonic()+min(10,req["deadline_seconds"]-1)
            while time.monotonic()<deadline:
                try:
                    cgroup,digest=pressure_observation(True)
                    emit({"handle":unit,"worker_harness_sha256":digest,"pressure_cgroup":cgroup}); return
                except (FileNotFoundError,RuntimeError):
                    time.sleep(0.1)
            raise RuntimeError("transient pressure scope did not report its bounded RUNNING inventory")
        finally:
            try: os.unlink(temp_name)
            except FileNotFoundError: pass
    if action=="pressure_status":
        complete=req.get("expect_pressure_completed") is True
        cgroup,digest=pressure_observation(not complete,complete)
        emit({"handle":scope_unit(),"worker_harness_sha256":digest,"pressure_cgroup":cgroup}); return
    if action=="pressure_stop":
        unit=scope_unit()
        try:
            raw,values=properties(unit,["ActiveState","ControlGroup"])
            if values.get("ActiveState")=="active":
                run([runtime["systemctl_path"],"stop",unit],timeout=20,maximum=65536)
        except Exception:
            pass
        deadline=time.monotonic()+10
        path=expected_scope_path()
        while time.monotonic()<deadline and path.exists():
            try:
                if not (path/"cgroup.procs").read_text().strip() and not any(p.is_dir() for p in path.iterdir()):
                    break
            except FileNotFoundError:
                break
            time.sleep(0.1)
        if path.exists():
            try:
                raw_procs=(path/"cgroup.procs").read_text()
            except FileNotFoundError:
                raw_procs=""
            if raw_procs.strip() or any(p.is_dir() for p in path.iterdir()):
                raise RuntimeError("pressure transient scope did not stop empty")
        scratch=Path(req["pressure"]["io_directory"])/("terrascale-d15-"+req["run_id"])
        if scratch.is_symlink():
            raise RuntimeError("pressure scratch path became a symlink")
        if scratch.exists():
            import shutil
            shutil.rmtree(scratch)
        emit({"handle":unit,"pressure_cgroup_process_pids":[],"pressure_cgroup_procs_raw":""}); return
    if action=="cleanup_verify":
        path=expected_scope_path()
        raw=""
        if path.exists():
            raw=(path/"cgroup.procs").read_text()
            if raw.strip() or any(p.is_dir() for p in path.iterdir()):
                raise RuntimeError("pressure cgroup remains populated")
        scratch=Path(req["pressure"]["io_directory"])/("terrascale-d15-"+req["run_id"])
        if scratch.exists() or scratch.is_symlink():
            raise RuntimeError("run-scoped pressure scratch remains")
        cleanup={"pressure_cgroup_procs_raw":raw,"pressure_child_cgroups":[],"scratch_paths":[]}
        intent=req.get("oom_restore_intent")
        if intent is not None:
            cleanup["oom_restore_verified"]=False
            cleanup["oom_restore_unresolved_reason"]="cleanup did not reconcile the pre-mutation restore intent"
            cleanup["oom_restore_target"]=intent.get("target")
            cleanup["oom_restore_cgroup_inode"]=None
            cleanup["current_database_memory_max_bytes"]=None
            try:
                target=intent["target"]
                cgroup,native,database=native_role_cgroups(
                    target,intent["native_runner_cgroup_path"],intent["database_cgroup_path"])
                if (target.get("kind")!="terrabase" or
                        intent.get("database_cgroup_path")!=req["protected_database_cgroup_path"] or
                        intent.get("native_runner_cgroup_path")!=req["native_runner_cgroup_path"]):
                    raise RuntimeError("restore intent differs from the qualifier-pinned native target")
                if intent.get("prior_memory_max_bytes")!=req["qualification"]["database_memory_max_bytes"]:
                    raise RuntimeError("restore intent prior cap differs from the signed TerraBase cap")
                try:
                    current_witness=process_witness(target["pid"])
                except FileNotFoundError:
                    current_witness=None
                if current_witness is not None and (
                        proc_stat_identity(current_witness["stat_raw"])[1]!=target["process_start"] or
                        proc_cgroup_path(current_witness["cgroup_raw"])!=target["cgroup"] or
                        current_witness["host_boot_id"]!=target["host_boot_id"]):
                    raise RuntimeError("OOM restore target PID was reused or moved to another cgroup")
                original_inode=intent.get("cgroup_inode")
                prior=intent["prior_memory_max_bytes"]
                temporary=intent["temporary_memory_max_bytes"]
                directory_fd=os.open(cgroup,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
                try:
                    opened_inode=os.fstat(directory_fd).st_ino
                    if (opened_inode!=original_inode or
                            cgroup.stat(follow_symlinks=False).st_ino!=original_inode):
                        raise RuntimeError("exact TerraBase cgroup identity changed before cleanup")
                    def read_limit_at(directory_fd):
                        limit_fd=os.open("memory.max",os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=directory_fd)
                        try:
                            raw_limit=os.read(limit_fd,65)
                            if len(raw_limit)>64:
                                raise RuntimeError("native role memory.max exceeded its read bound")
                            return int(raw_limit.decode("ascii").strip())
                        finally:
                            os.close(limit_fd)
                    current=read_limit_at(directory_fd)
                    cleanup["oom_restore_cgroup_inode"]=opened_inode
                    cleanup["current_database_memory_max_bytes"]=current
                    if current==temporary:
                        if (os.fstat(directory_fd).st_ino!=original_inode or
                                cgroup.stat(follow_symlinks=False).st_ino!=original_inode):
                            raise RuntimeError("exact TerraBase cgroup path changed before cap restore")
                        memory_fd=os.open("memory.max",os.O_WRONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=directory_fd)
                        try:
                            os.lseek(memory_fd,0,os.SEEK_SET)
                            limit_bytes=str(prior).encode()
                            if os.write(memory_fd,limit_bytes)!=len(limit_bytes):
                                raise RuntimeError("native role memory.max restore write was incomplete")
                        finally:
                            os.close(memory_fd)
                        current=read_limit_at(directory_fd)
                        if (os.fstat(directory_fd).st_ino!=original_inode or
                                cgroup.stat(follow_symlinks=False).st_ino!=original_inode or current!=prior):
                            raise RuntimeError("exact TerraBase role memory.max restore could not be verified")
                        cleanup["current_database_memory_max_bytes"]=current
                    elif current!=prior:
                        raise RuntimeError("exact TerraBase role has an unknown cap or changed cgroup identity")
                    elif (os.fstat(directory_fd).st_ino!=original_inode or
                            cgroup.stat(follow_symlinks=False).st_ino!=original_inode):
                        raise RuntimeError("exact TerraBase cgroup path changed during cap verification")
                    cleanup["oom_restore_verified"]=True
                    cleanup["oom_restore_unresolved_reason"]=None
                finally:
                    os.close(directory_fd)
            except Exception as error:
                detail=str(error).replace("\n"," ").replace("\r"," ")
                cleanup["oom_restore_unresolved_reason"]=(type(error).__name__+": "+detail)[:256]
        emit({"cleanup":cleanup}); return
    if action=="oom_watermark":
        target=req["oom_target"]
        reported,native,database=native_role_cgroups(
            target,req["native_runner_cgroup_path"],req["protected_database_cgroup_path"])
        witness=process_witness(target["pid"])
        if (proc_stat_identity(witness["stat_raw"])[1]!=target["process_start"] or
                proc_cgroup_path(witness["cgroup_raw"])!=target["cgroup"] or
                witness["host_boot_id"]!=target["host_boot_id"]):
            raise RuntimeError("OOM restore intent differs from the current native process witness")
        prior=int((reported/"memory.max").read_text().strip())
        signed=req["qualification"]["database_memory_max_bytes"]
        if prior!=signed:
            raise RuntimeError("native TerraBase role cap differs from the signed pre-mutation cap")
        rows=journal_records()
        if not rows:
            raise RuntimeError("kernel journal has no record from which to bind a pre-pressure cursor")
        row=rows[-1]
        fault=req["pressure"]["oom_fault"]
        intent={"target":{key:target[key] for key in
                 ("kind","pid","process_start","process_nonce","cgroup","host_boot_id")},
                "native_runner_cgroup_path":req["native_runner_cgroup_path"],
                "database_cgroup_path":req["protected_database_cgroup_path"],
                "cgroup_inode":reported.stat(follow_symlinks=False).st_ino,
                "prior_memory_max_bytes":prior,
                "temporary_memory_max_bytes":fault["target_memory_max_bytes"]}
        emit({"journal_watermark_raw_record":row["raw_record"],
              "journal_watermark_raw_record_sha256":row["raw_record_sha256"],"events":[],
              "oom_restore_intent":intent}); return
    if action=="oom_collect":
        watermark=req["journal_watermark"]
        rows=journal_records(watermark["cursor"])
        emit({"events":[{"source":row["source"],"raw_record":row["raw_record"],
              "raw_record_sha256":row["raw_record_sha256"]} for row in rows]}); return
    if action=="oom_fault":
        pressure,_=pressure_module()
        target=req["oom_target"]
        reported,native,db=native_role_cgroups(
            target,req["native_runner_cgroup_path"],req["protected_database_cgroup_path"])
        intent=req.get("oom_restore_intent")
        identity={key:target[key] for key in
                  ("kind","pid","process_start","process_nonce","cgroup","host_boot_id")}
        if (type(intent) is not dict or intent.get("target")!=identity or
                intent.get("native_runner_cgroup_path")!=req["native_runner_cgroup_path"] or
                intent.get("database_cgroup_path")!=req["protected_database_cgroup_path"] or
                intent.get("prior_memory_max_bytes")!=req["qualification"]["database_memory_max_bytes"] or
                intent.get("temporary_memory_max_bytes")!=req["pressure"]["oom_fault"]["target_memory_max_bytes"]):
            raise RuntimeError("OOM mutation lacks the exact pre-mutation native role restore intent")
        pid=target["pid"]
        witness=process_witness(pid)
        start,_=proc_stat_identity(witness["stat_raw"])
        if (start!=pid or proc_stat_identity(witness["stat_raw"])[1]!=target["process_start"] or
                proc_cgroup_path(witness["cgroup_raw"])!=target["cgroup"] or
                witness["host_boot_id"]!=target["host_boot_id"]):
            raise RuntimeError("OOM fault process witness differs from the latest accepted host report")
        desired=req["pressure"]["oom_fault"]["target_memory_max_bytes"]
        signed=req["qualification"]["database_memory_max_bytes"]
        directory_fd=os.open(reported,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
        original_inode=os.fstat(directory_fd).st_ino
        memory_fd=None
        events=[]; matching=None; restore_method=None; restored=None
        mutation_attempted=False
        def read_at(name):
            fd=os.open(name,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=directory_fd)
            try:
                raw=os.read(fd,4097)
                if len(raw)>4096:
                    raise RuntimeError("native role cgroup file exceeded its read bound")
                return raw.decode("ascii")
            finally:
                os.close(fd)
        def current_members():
            return sorted(int(line) for line in read_at("cgroup.procs").splitlines() if line)
        def child_cgroups():
            children=[]
            for name in os.listdir(directory_fd):
                try:
                    info=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
                except FileNotFoundError:
                    raise RuntimeError("native role cgroup changed while checking child groups")
                if stat.S_ISDIR(info.st_mode):
                    children.append(name)
            return children
        def set_limit(fd,value):
            os.lseek(fd,0,os.SEEK_SET)
            raw=str(value).encode()
            if os.write(fd,raw)!=len(raw):
                raise RuntimeError("native role memory.max write was incomplete")
        try:
            if (original_inode!=intent.get("cgroup_inode") or
                    reported.stat(follow_symlinks=False).st_ino!=original_inode):
                raise RuntimeError("exact TerraBase cgroup path changed before OOM cap mutation")
            memory_fd=os.open("memory.max",os.O_WRONLY|getattr(os,"O_NOFOLLOW",0),dir_fd=directory_fd)
            if (os.fstat(directory_fd).st_ino!=original_inode or
                    reported.stat(follow_symlinks=False).st_ino!=original_inode):
                raise RuntimeError("exact TerraBase cgroup path changed before OOM cap mutation")
            latest=process_witness(pid)
            if (proc_stat_identity(latest["stat_raw"])[1]!=target["process_start"] or
                    proc_cgroup_path(latest["cgroup_raw"])!=target["cgroup"] or
                    latest["host_boot_id"]!=target["host_boot_id"]):
                raise RuntimeError("OOM fault process witness changed before cap mutation")
            prior=int(read_at("memory.max").strip())
            current=int(read_at("memory.current").strip())
            members=current_members()
            child_groups=child_cgroups()
            if (prior!=signed or desired>=prior or current<=desired or
                    members!=[pid] or child_groups):
                raise RuntimeError("native role is not a single-process bounded OOM target above the requested cap")
            mutation_attempted=True
            set_limit(memory_fd,desired)
            if (os.fstat(directory_fd).st_ino!=original_inode or
                    reported.stat(follow_symlinks=False).st_ino!=original_inode):
                raise RuntimeError("exact TerraBase cgroup path changed during OOM cap mutation")
            deadline=time.monotonic()+req["pressure"]["oom_fault"]["deadline_seconds"]
            cursor=req["journal_watermark"]["cursor"]
            while time.monotonic()<deadline:
                events=journal_records(cursor)
                for row in events:
                    parsed=row["parsed"]
                    if parsed["victim_pid"]==pid and parsed["cgroup_path"]==target["cgroup"]:
                        matching=parsed; break
                if matching:
                    try:
                        stat_now=(Path("/proc")/str(pid)/"stat").read_text()
                        if proc_stat_identity(stat_now)[1]!=target["process_start"]:
                            break
                    except FileNotFoundError:
                        break
                time.sleep(0.15)
            if matching is None:
                raise RuntimeError("kernel journal did not identify TerraBase as the bounded OOM victim")
            try:
                stat_now=(Path("/proc")/str(pid)/"stat").read_text()
                if proc_stat_identity(stat_now)[1]==target["process_start"]:
                    raise RuntimeError("kernel OOM record arrived before the exact TerraBase process exited")
            except FileNotFoundError:
                pass
        finally:
            try:
                if mutation_attempted and memory_fd is not None:
                    try:
                        set_limit(memory_fd,prior)
                        restored=int(read_at("memory.max").strip())
                        if (restored==prior and os.fstat(directory_fd).st_ino==original_inode and
                                reported.stat(follow_symlinks=False).st_ino==original_inode):
                            restore_method="same_cgroup_fd"
                    except (OSError,FileNotFoundError):
                        pass
                    if restore_method is None:
                        try:
                            current_path=safe_cgroup(target["cgroup"])
                            restored=int((current_path/"memory.max").read_text().strip())
                            if restored==prior and current_path.stat().st_ino!=original_inode:
                                restore_method="native_role_recreated"
                        except Exception:
                            pass
                    if restored!=prior or restore_method is None:
                        raise RuntimeError("exact TerraBase role memory.max could not be restored and verified")
            finally:
                if memory_fd is not None:
                    os.close(memory_fd)
                os.close(directory_fd)
        watermark_cursor=req["journal_watermark"]["cursor"]
        rows=journal_records(watermark_cursor)
        out_events=[{"source":row["source"],"raw_record":row["raw_record"],
                     "raw_record_sha256":row["raw_record_sha256"]} for row in rows]
        receipt={"target":{key:target[key] for key in ("kind","pid","process_start","process_nonce","cgroup","host_boot_id")},
            "prior_memory_max_bytes":prior,"temporary_memory_max_bytes":desired,
            "observed_memory_current_bytes":current,"target_cgroup_members_before":members,
            "target_child_cgroups_before":child_groups,"target_cgroup_inode_before":original_inode,
            "restored_memory_max_bytes":restored,"restore_method":restore_method,"restore_verified":True}
        emit({"events":out_events,"memory_limit_receipt":receipt}); return
    if action=="failure_inject":
        target=req["target_process"]; pid=target["pid"]
        if target["kind"] not in {"terrabase","host_manager"}:
            raise RuntimeError("failure target kind is not an approved SIGKILL scenario")
        if target["kind"]=="terrabase":
            native_role_cgroups(target,req["native_runner_cgroup_path"],
                                req["protected_database_cgroup_path"])
        current=process_witness(pid)
        if (proc_stat_identity(current["stat_raw"])[1]!=target["process_start"] or
                proc_cgroup_path(current["cgroup_raw"])!=target["cgroup"] or
                current["host_boot_id"]!=target["host_boot_id"]):
            raise RuntimeError("SIGKILL target changed from its immediate accepted witness")
        if target["kind"]=="host_manager":
            raw,values=properties(target["unit"],["ActiveState","MainPID","ControlGroup"])
            if (values.get("ActiveState")!="active" or int(values.get("MainPID","0"))!=pid or
                    values.get("ControlGroup","").rstrip("/")+"/supervisor"!=target["cgroup"]):
                raise RuntimeError("host-manager unit no longer identifies the witnessed PID")
        requested=dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")
        os.kill(pid,signal.SIGKILL)
        completed=dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00","Z")
        emit({"action_receipt":{"target_process":target,"signal":"SIGKILL",
            "requested_at_utc":requested,"completed_at_utc":completed,"exit_status":0}}); return
    raise RuntimeError("unsupported fixed remote action")

try:
    main()
except Exception as error:
    sys.stderr.write("alpha remote action failed: "+type(error).__name__+"\n")
    sys.exit(2)
'''


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _read_request() -> dict[str, Any]:
    wire = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(wire) > MAX_REQUEST_BYTES:
        raise pressure.HarnessError("adapter input exceeds its fixed bound")
    try:
        value = json.loads(wire, object_pairs_hook=pressure.unique_json_object)
    except json.JSONDecodeError as error:
        raise pressure.HarnessError("adapter input is invalid JSON") from error
    if type(value) is not dict or value.get("schema") != pressure.ADAPTER_INPUT_SCHEMA:
        raise pressure.HarnessError("adapter input schema is invalid")
    return value


def _verify_hash(path_value: object, digest_value: object, label: str, *, executable: bool = False) -> Path:
    if not isinstance(path_value, str) or not Path(path_value).is_absolute():
        raise pressure.HarnessError(f"{label} path is not absolute")
    path = Path(path_value)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > pressure.MAX_PINNED_FILE_BYTES:
            raise pressure.HarnessError(f"{label} is not a bounded regular file")
        data = path.read_bytes()
    except OSError as error:
        raise pressure.HarnessError(f"{label} is unavailable") from error
    actual = hashlib.sha256(data).hexdigest()
    if not pressure.HASH_RE.fullmatch(str(digest_value or "")) or actual != digest_value:
        raise pressure.HarnessError(f"{label} differs from its SHA-256 pin")
    if executable and (not info.st_mode & 0o111 or info.st_mode & 0o022):
        raise pressure.HarnessError(f"{label} is not an executable immutable file")
    return path


def _verify_private(path_value: object, label: str) -> Path:
    if not isinstance(path_value, str) or not Path(path_value).is_absolute():
        raise pressure.HarnessError(f"{label} path is not absolute")
    path = Path(path_value)
    try:
        info = path.lstat()
    except OSError as error:
        raise pressure.HarnessError(f"{label} is unavailable") from error
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
            info.st_mode & 0o077 or not info.st_mode & 0o400):
        raise pressure.HarnessError(f"{label} must be a private current-user-owned regular file")
    return path


def _verify_transport(request: dict[str, Any]) -> None:
    transport = request["transport"]
    operator = transport["operator"]
    _verify_hash(operator["executable_path"], operator["executable_sha256"], "operator executable", executable=True)
    _verify_pinned_file(operator["config_path"], operator["config_sha256"], "operator config")
    ssh = transport["ssh"]
    _verify_hash(ssh["executable_path"], ssh["executable_sha256"], "SSH executable", executable=True)
    for label in ("source", "peer", "controller"):
        target = ssh["targets"][label]
        _verify_pinned_file(target["known_hosts_path"], target["known_hosts_sha256"],
                            f"{label} known_hosts")
        _verify_private(target["identity_file_path"], f"{label} SSH identity")
    https = transport["https"]
    _verify_pinned_file(https["ca_bundle_path"], https["ca_bundle_sha256"], "TLS CA bundle")
    for label in ("source", "peer"):
        _verify_private(https[f"{label}_credential_file"], f"{label} API credential")
    adapter = request.get("adapter_source_path")
    if (not isinstance(adapter, str) or Path(adapter).name != "alpha_adapter.py" or
            Path(adapter).resolve() != Path(__file__).resolve()):
        raise pressure.HarnessError("request adapter source path is not the pinned alpha adapter")
    _verify_hash(adapter, request.get("adapter_source_sha256"), "alpha adapter source")


def _verify_pinned_file(path_value: object, digest_value: object, label: str) -> None:
    missing: list[str] = []
    pressure.verify_pinned_file(path_value, digest_value, label, missing)
    if missing:
        raise pressure.HarnessError("; ".join(missing))


def _run_bounded(argv: list[str], *, input_bytes: bytes | None, timeout: float,
                 output_limit: int = MAX_REMOTE_OUTPUT_BYTES) -> bytes:
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, close_fds=True,
                               env={"HOME": "/", "LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"})
    try:
        stdout, stderr = pressure.communicate_bounded(process, input_bytes or b"", timeout,
                                                       output_limit)
    except (subprocess.TimeoutExpired, pressure.HarnessError):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=5)
        raise
    if process.returncode != 0:
        raise pressure.HarnessError("pinned transport command failed")
    return stdout


def _ssh(request: dict[str, Any], label: str, action: str,
         payload: dict[str, Any] | None = None) -> dict[str, Any]:
    transport = request["transport"]
    target = transport["ssh"]["targets"][label]
    remote_request = dict(request)
    remote_request["remote_payload"] = payload or {}
    wire = json.dumps(remote_request, sort_keys=True, separators=(",", ":")).encode()
    if len(wire) > MAX_REQUEST_BYTES:
        raise pressure.HarnessError("SSH helper input exceeds its fixed bound")
    remote_command = shlex.join([transport["runtime"]["sudo_path"], "-n", "--",
                                 transport["runtime"]["remote_python_path"], "-c",
                                 REMOTE_ACTIONS, action])
    argv = [transport["ssh"]["executable_path"], "-F", "/dev/null",
            "-oBatchMode=yes", "-oStrictHostKeyChecking=yes", "-oUpdateHostKeys=no",
            "-oUserKnownHostsFile=" + target["known_hosts_path"],
            "-oGlobalKnownHostsFile=/dev/null", "-oCheckHostIP=no",
            "-oVerifyHostKeyDNS=no", "-oHostKeyAlias=" + target["host_key_alias"],
            "-oIdentitiesOnly=yes", "-oIdentityAgent=none", "-oClearAllForwardings=yes",
            "-oPasswordAuthentication=no", "-oKbdInteractiveAuthentication=no",
            "-oProxyCommand=none", "-oConnectTimeout=10", "-i", target["identity_file_path"],
            "-p", str(target["port"]), target["user"] + "@" + target["address"], remote_command]
    stdout = _run_bounded(argv, input_bytes=wire, timeout=request["deadline_seconds"],
                          output_limit=MAX_REMOTE_OUTPUT_BYTES)
    try:
        result = json.loads(stdout, object_pairs_hook=pressure.unique_json_object)
    except json.JSONDecodeError as error:
        raise pressure.HarnessError("remote pinned action returned invalid JSON") from error
    if type(result) is not dict:
        raise pressure.HarnessError("remote pinned action did not return one JSON object")
    return result


def _operator_hosts(request: dict[str, Any]) -> str:
    operator = request["transport"]["operator"]
    output = _run_bounded([operator["executable_path"], "operator", "hosts", "--config",
                           operator["config_path"]], input_bytes=None,
                          timeout=request["deadline_seconds"], output_limit=MAX_REMOTE_OUTPUT_BYTES)
    raw = output.decode("utf-8")
    try:
        hosts = json.loads(raw, object_pairs_hook=pressure.unique_json_object)
    except json.JSONDecodeError as error:
        raise pressure.HarnessError("operator hosts command did not return its raw HostStatus JSON array") from error
    if type(hosts) is not list:
        raise pressure.HarnessError("operator hosts command did not return a HostStatus JSON array")
    return raw


def _host_rows(raw: str, request: dict[str, Any]) -> dict[str, dict[str, Any]]:
    hosts = json.loads(raw, object_pairs_hook=pressure.unique_json_object)
    selected: dict[str, dict[str, Any]] = {}
    targets = request["transport"]["ssh"]["targets"]
    for label in ("source", "peer"):
        expected = request["managed_member"][label]
        rows = []
        for host in hosts:
            if type(host) is not dict or type(host.get("registration")) is not dict:
                continue
            registration = host["registration"]
            binding = registration.get("managed_member")
            if (registration.get("cell") == expected["cell"] and
                    registration.get("node") == expected["node"] and
                    registration.get("environment") == expected["environment"] and
                    type(binding) is dict and binding.get("scope") == expected["scope"]):
                rows.append(host)
        if len(rows) != 1:
            raise pressure.HarnessError(f"operator hosts returned {len(rows)} exact {label} registrations")
        registration = rows[0]["registration"]
        oci = registration.get("managed_oci")
        if type(oci) is not dict or oci.get("instance_id") != targets[label]["oci_instance_id"]:
            raise pressure.HarnessError(f"operator HostStatus does not bind the pinned {label} OCI instance")
        selected[label] = rows[0]
    return selected


def _host_status(request: dict[str, Any]) -> dict[str, Any]:
    raw = _operator_hosts(request)
    selected = _host_rows(raw, request)
    witnesses = {}
    for label in ("source", "peer"):
        reports = selected[label].get("reports")
        expected = request["managed_member"][label]
        matches = [report for report in reports if type(report) is dict and
                   report.get("cell") == expected["cell"] and report.get("node") == expected["node"] and
                   report.get("environment") == expected["environment"] and report.get("role") == expected["role"]]
        if len(matches) != 1 or type(matches[0].get("managed")) is not dict:
            raise pressure.HarnessError(f"operator HostStatus omits one exact {label} managed report")
        pid = matches[0]["managed"].get("process_pid")
        if type(pid) is not int or pid <= 1:
            raise pressure.HarnessError(f"operator HostStatus has no live {label} process PID")
        witnesses[label] = _ssh(request, label, "proc_witness", {"pid": pid})
    return {"operator_hosts_json": raw,
            "operator_hosts_sha256": hashlib.sha256(raw.encode()).hexdigest(),
            "process_witnesses": witnesses}


def _service_state(request: dict[str, Any]) -> dict[str, Any]:
    guest_role = request["guest_role"]
    evidence = _ssh(request, "source" if guest_role == "host" else "controller", "service_state")
    if set(evidence) != {"guest_role", "units", "host_boot_id"}:
        raise pressure.HarnessError("remote service state has an unexpected evidence shape")
    return evidence


def _qualify(request: dict[str, Any]) -> dict[str, Any]:
    guest_role = request["guest_role"]
    result = _ssh(request, "source" if guest_role == "host" else "controller", "qualify")
    summary = result.get("summary")
    commands = result.get("commands_log")
    if type(summary) is not dict or not isinstance(commands, str):
        raise pressure.HarnessError("remote qualifier omitted raw summary or commands log")
    summary_wire = (json.dumps(summary, sort_keys=True, indent=2) + "\n").encode()
    return {"summary": summary,
            "probe_evidence": {"fresh_for_request_id": request["request_id"],
                               "summary_sha256": hashlib.sha256(summary_wire).hexdigest(),
                               "commands_log": commands,
                               "commands_sha256": hashlib.sha256(commands.encode()).hexdigest()}}


def _credential_token(path_value: str) -> str:
    path = _verify_private(path_value, "HTTPS API credential")
    value = path.read_text(encoding="utf-8").strip()
    if not value or "\n" in value or "\r" in value:
        raise pressure.HarnessError("HTTPS API credential file must contain one private bearer token")
    return value


def _https_request(request: dict[str, Any], label: str, method: str, path: str,
                   body: bytes | None = None) -> bytes:
    https = request["transport"]["https"]
    endpoint = urllib.parse.urlsplit(https[f"{label}_base_url"])
    if endpoint.scheme != "https" or endpoint.hostname is None:
        raise pressure.HarnessError("HTTPS endpoint failed its pinned origin validation")
    context = ssl.create_default_context(cafile=https["ca_bundle_path"])
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port or 443,
                                             context=context,
                                             timeout=request["deadline_seconds"])
    try:
        connection.connect()
        if connection.sock is None:
            raise pressure.HarnessError(f"{label} HTTPS connection lost its verified TLS socket")
        peer_digest = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest()
        expected_digest = request["managed_member"][label]["authority"]["tls_leaf_sha256"]
        if peer_digest != expected_digest:
            raise pressure.HarnessError(f"{label} HTTPS peer certificate differs from its member authority pin")
        headers = {"Authorization": "Bearer " + _credential_token(https[f"{label}_credential_file"]),
                   "Accept": "application/json", "Connection": "close"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        if response.status != 200 or response.getheader("Content-Type", "").split(";", 1)[0] != "application/json":
            raise pressure.HarnessError(f"{label} HTTPS data request did not return JSON HTTP 200")
        if response.length is not None and response.length > 65536:
            raise pressure.HarnessError(f"{label} HTTPS response exceeds its evidence bound")
        result = response.read(65537)
        if len(result) > 65536:
            raise pressure.HarnessError(f"{label} HTTPS response exceeds its evidence bound")
        return result
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise pressure.HarnessError(f"{label} HTTPS request failed with verified TLS") from error
    finally:
        connection.close()


def _database_progress(request: dict[str, Any]) -> dict[str, Any]:
    member = request["managed_member"]
    source_scope = member["source"]["scope"]
    document = member["document"]
    document_id = request["document_id"]
    transaction = request["transaction_id"]
    value = request["value"]
    write_path = (f"/v1/tenants/{source_scope['tenant_id']}/databases/{source_scope['database_id']}"
                  f"/shards/{source_scope['shard_id']}/transactions")
    read_path = (f"/v1/tenants/{source_scope['tenant_id']}/databases/{source_scope['database_id']}"
                 f"/shards/{source_scope['shard_id']}/collections/{document['collection_id']}"
                 f"/documents/{document_id}")
    write_request = {"version": 1, "transaction_id": transaction, "writes": [{
        "collection": document["collection_id"], "document": document_id,
        "schema_generation": str(document["schema_generation"]),
        "schema_digest": document["schema_digest"], "observed": [],
        "value": {"kind": "live", "fields": [{"id": document["field_id"],
                                                   "value": {"type": "i64", "value": str(value)}}]},
    }]}
    request_raw = json.dumps(write_request, separators=(",", ":"), sort_keys=True)
    started = time.monotonic()
    receipt = _https_request(request, "source", "POST", write_path, request_raw.encode())
    point = _https_request(request, "peer", "GET", read_path)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    if elapsed_ms > request["deadline_seconds"] * 1000:
        raise pressure.HarnessError("ObjectDurable write and peer point read exceeded their pinned deadline")
    return {"write_path": write_path, "peer_read_path": read_path, "document_id": document_id,
            "transaction_request_raw": request_raw,
            "transaction_request_sha256": hashlib.sha256(request_raw.encode()).hexdigest(),
            "write_receipt_raw": receipt.decode("utf-8"),
            "write_receipt_sha256": hashlib.sha256(receipt).hexdigest(),
            "peer_read_raw": point.decode("utf-8"),
            "peer_read_sha256": hashlib.sha256(point).hexdigest(),
            "operation_elapsed_ms": elapsed_ms}


def _dispatch(request: dict[str, Any]) -> dict[str, Any]:
    role = request["role"]
    if role in {"target_identity", "host_status"}:
        raw = _operator_hosts(request)
        rows = _host_rows(raw, request)
        if role == "target_identity":
            source = _ssh(request, "source", "uname")
            peer = _ssh(request, "peer", "uname")
            controller = _ssh(request, "controller", "uname")
            metadata = _ssh(request, "source", "oci_metadata")
            controller_metadata = _ssh(request, "controller", "oci_metadata")
            if (source.get("architecture") != request["identity"]["architecture"] or
                    peer.get("architecture") != request["identity"]["architecture"] or
                    controller.get("architecture") != request["controller_identity"]["architecture"]):
                raise pressure.HarnessError("SSH target architecture differs from the pinned ARM identity")
            if set(metadata) != {"oci_metadata"} or set(controller_metadata) != {"oci_metadata"}:
                raise pressure.HarnessError("OCI metadata action returned an unexpected evidence shape")
            return {
                "operator_hosts_json": raw,
                "operator_hosts_sha256": hashlib.sha256(raw.encode()).hexdigest(),
                "architecture_by_member": {
                    "source": source["architecture"], "peer": peer["architecture"],
                    "controller": controller["architecture"],
                },
                "source_oci_metadata": metadata["oci_metadata"],
                "controller_oci_metadata": controller_metadata["oci_metadata"],
            }
        witnesses = {}
        for label in ("source", "peer"):
            expected = request["managed_member"][label]
            reports = rows[label].get("reports")
            matches = [row for row in reports if type(row) is dict and
                       row.get("cell")==expected["cell"] and row.get("node")==expected["node"] and
                       row.get("environment")==expected["environment"] and row.get("role")==expected["role"]]
            if len(matches)!=1 or type(matches[0].get("managed")) is not dict:
                raise pressure.HarnessError(f"operator hosts omitted the exact {label} managed report")
            pid=matches[0]["managed"].get("process_pid")
            if type(pid) is not int or pid<=1:
                raise pressure.HarnessError(f"operator hosts report has no {label} process PID")
            witnesses[label]=_ssh(request,label,"proc_witness",{"pid":pid})
        return {"operator_hosts_json":raw,"operator_hosts_sha256":hashlib.sha256(raw.encode()).hexdigest(),
                "process_witnesses":witnesses}
    if role == "service_state":
        return _service_state(request)
    if role == "qualify":
        return _qualify(request)
    if role == "database_progress":
        return _database_progress(request)
    if role == "pressure_start":
        result=_ssh(request,"source","pressure_start")
        if set(result)!={"handle","worker_harness_sha256","pressure_cgroup"}:
            raise pressure.HarnessError("pressure launcher returned an unexpected evidence shape")
        return result
    if role == "pressure_status":
        result=_ssh(request,"source","pressure_status")
        return result
    if role in {"pressure_stop","cleanup_verify"}:
        result=_ssh(request,"source",role)
        return result
    if role == "failure_inject":
        return _ssh(request,"source","failure_inject")
    if role == "kernel_oom_evidence":
        if request["phase"] == "before":
            return _ssh(request,"source","oom_watermark")
        if request.get("wait_for_event") is True:
            return _ssh(request,"source","oom_fault")
        return _ssh(request,"source","oom_collect")
    raise pressure.HarnessError("alpha adapter received an unsupported role")


def main() -> int:
    try:
        request = _read_request()
        _verify_transport(request)
        evidence = _dispatch(request)
        response = {"schema": pressure.ADAPTER_RESULT_SCHEMA,
                    "request_id": request["request_id"], "contract_id": request["contract_id"],
                    "role": request["role"], "status": "PASS", "observed_at_utc": _now(),
                    "evidence": evidence}
        wire = json.dumps(response, separators=(",", ":"), sort_keys=True).encode()
        if len(wire) > MAX_REMOTE_OUTPUT_BYTES:
            raise pressure.HarnessError("alpha adapter result exceeds its fixed evidence bound")
        sys.stdout.buffer.write(wire + b"\n")
        return 0
    except (pressure.HarnessError, OSError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError) as error:
        # Transport output may contain bearer credentials or owner configuration.
        sys.stderr.write("alpha adapter failed: " + type(error).__name__ + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
