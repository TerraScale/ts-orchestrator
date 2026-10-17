import pathlib, subprocess, json, os, time, fcntl, datetime, hashlib, signal
OUT=pathlib.Path(__file__).parent
PACKET=pathlib.Path('/tmp/ts-oci-sdk-volume-retirement-source-artifact-tests')
EXPECTED_PROOF_SHA='ce906c9e176236b8f606ceacfc52ff1e658b957deaaf2d544b526d512a7b4703'
EXPECTED_PLAN_SHA='a8c45af1191806faa09c42781adf62580ea52e9ff19ae5591346a6364a81b077'
sha=lambda data:hashlib.sha256(data).hexdigest()
assert sha((PACKET/'source-removals.json').read_bytes())==EXPECTED_PROOF_SHA
assert sha((PACKET/'compile-plan.json').read_bytes())==EXPECTED_PLAN_SHA
proof=json.loads((PACKET/'source-removals.json').read_bytes());plan=json.loads((PACKET/'compile-plan.json').read_bytes())
SOURCE=pathlib.Path(plan['cwd']);ENV=plan['effective_child_environment'];ARGV=plan['argv'];BINARY=pathlib.Path(ARGV[ARGV.index('-o')+1])
assert not BINARY.exists(),'external binary already exists; one attempt only'
def write(name,value):(OUT/name).write_text(json.dumps(value,indent=2)+'\n')
def git(*args):return subprocess.check_output(['git',*args],cwd=SOURCE,text=True).strip()
def snapshot():
    manifest=[]
    for rec in subprocess.check_output(['git','ls-files','--stage','-z'],cwd=SOURCE).split(b'\0'):
        if not rec:continue
        meta,path=rec.split(b'\t',1);mode,blob,stage=meta.decode().split();assert stage=='0'
        p=SOURCE/path.decode();data=os.readlink(p).encode() if mode=='120000' else p.read_bytes()
        manifest.append({'path':path.decode(),'mode':mode,'blob':blob,'sha256':sha(data)})
    for record in proof['actual_file_changes']:assert sha((SOURCE/record['file']).read_bytes())==record['after_sha256']
    return {'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain=v1','--untracked-files=all'),'tracked_files':len(manifest),'full_tracked_aggregate_sha256':sha(json.dumps(manifest,sort_keys=True).encode()),'source_proof_sha256':sha((PACKET/'source-removals.json').read_bytes()),'changed_paths_from_additive':git('diff','--name-only',proof['base_head'],'HEAD').splitlines()}
def resources():
    mem={line.split(':')[0]:line.split(':')[1].strip() for line in pathlib.Path('/proc/meminfo').read_text().splitlines()}
    compilers=[]
    for p in pathlib.Path('/proc').glob('[0-9]*/exe'):
        try:
            if p.resolve().name=='compile':compilers.append(int(p.parent.name))
        except OSError:pass
    return {'available_ram_bytes':int(mem['MemAvailable'].split()[0])*1024,'load1':os.getloadavg()[0],'compiler_pids':compilers,'compiler_count':len(compilers)}
def group_members(pgid):
    found=[]
    for p in pathlib.Path('/proc').glob('[0-9]*/stat'):
        try:
            fields=p.read_text().rsplit(')',1)[1].split()
            if int(fields[2])==pgid:found.append({'pid':int(p.parent.name),'state':fields[0]})
        except (OSError,ValueError,IndexError):pass
    return found
result={'owner':'/root/qa_integrator/artifact_tests','attempt':1,'runtime_executed':False,'default_vet':True,'default_tags':True,'source':str(SOURCE),'head':plan['head'],'tree':plan['tree'],'argv':ARGV,'env':ENV,'lock':plan['lock'],'wrapper_pid':os.getpid(),'source_proof_sha256':EXPECTED_PROOF_SHA,'compile_plan_sha256':EXPECTED_PLAN_SHA,'runner_sha256':sha(pathlib.Path(__file__).read_bytes()),'source_adoption':False,'count_or_ledger_update':False}
with open(plan['lock'],'a+') as lock:
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        result.update(state='LOCK_BUSY_NOT_LAUNCHED',lock_acquired=False);write('result.json',result);raise SystemExit(73)
    result['lock_acquired']=True
    try:
        result['source_before']=snapshot();assert result['source_before']['head']==plan['head'] and result['source_before']['tree']==plan['tree'] and not result['source_before']['status']
        result['preflight']=resources()
        if result['preflight']['available_ram_bytes']<16*1024**3 or result['preflight']['load1']>=12 or result['preflight']['compiler_count']>4:
            result['state']='RESOURCE_PREFLIGHT_NOT_LAUNCHED'
        else:
            result['started_at']=datetime.datetime.now(datetime.timezone.utc).isoformat();write('started.json',result);clock=time.monotonic()
            with (OUT/'compile.stdout').open('xb') as stdout,(OUT/'compile.stderr').open('xb') as stderr:
                proc=subprocess.Popen(ARGV,cwd=SOURCE,env=ENV,stdout=stdout,stderr=stderr,start_new_session=True)
                result['command_pid']=proc.pid;write('running.json',result)
                print(json.dumps({'state':'COMPILE_STARTED','pid':proc.pid,'handle':str(OUT)}),flush=True)
                proc.wait()
            result.update(exit_code=proc.returncode,elapsed_seconds=time.monotonic()-clock,finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
            result['cleanup_before']=group_members(proc.pid)
            if any(p['state']!='Z' for p in result['cleanup_before']):
                os.killpg(proc.pid,signal.SIGTERM);deadline=time.monotonic()+5
                while time.monotonic()<deadline and any(p['state']!='Z' for p in group_members(proc.pid)):time.sleep(.1)
                if any(p['state']!='Z' for p in group_members(proc.pid)):os.killpg(proc.pid,signal.SIGKILL)
            result['cleanup_after']=group_members(proc.pid);result['cleanup_joined']=not any(p['state']!='Z' for p in result['cleanup_after'])
            if BINARY.exists():
                os.chmod(BINARY,0o600);result['external_binary']={'path':str(BINARY),'mode':oct(BINARY.stat().st_mode&0o777),'bytes':BINARY.stat().st_size,'sha256':sha(BINARY.read_bytes()),'elf':BINARY.read_bytes()[:4]==b'\x7fELF','never_executed':True}
            result['source_after']=snapshot();result['source_unchanged']=result['source_before']==result['source_after']
            result['raw_sha256']={name:sha((OUT/name).read_bytes()) for name in ['compile.stdout','compile.stderr']}
            result['state']='PASS' if result['exit_code']==0 and result['source_unchanged'] and result['cleanup_joined'] and result.get('external_binary',{}).get('elf') else 'NOT_QUALIFIED'
    except Exception as error:result.update(state='RUNNER_ERROR',error=repr(error))
    finally:
        fcntl.flock(lock,fcntl.LOCK_UN);result['lock_released']=True;write('result.json',result)
print(json.dumps(result,indent=2),flush=True)
raise SystemExit(0 if result['state']=='PASS' else 1)
