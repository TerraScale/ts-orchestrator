import pathlib, json, hashlib, subprocess, os, time, datetime, fcntl, signal
OUT=pathlib.Path(__file__).parent
SOURCE=pathlib.Path('/tmp/ts-oci-sdk-volume-socket-batch')
HEAD='e5e72bbbfbf83f02c251ffe1fa98246137a3cedc'
TREE='727f82020910c067fd106af5094a0e81d736dea2'
LOCK='/tmp/ts-orch-refactor-short-check-a.lock'
GO='/home/mariogk/.local/share/mise/installs/go/1.27.1/bin/go'
ENV={'HOME':'/home/mariogk','PATH':'/home/mariogk/.local/share/mise/installs/go/1.27.1/bin:/run/current-system/sw/bin','LANG':'C.UTF-8','GOMAXPROCS':'2','GOFLAGS':'-p=2','GOTOOLCHAIN':'local'}
SELECTOR='^TestSDKSocket(LaunchPreservesSignedProfileAndResponse|LaunchRejectsInexactSizingBeforeAnyRequest|ManagedReadbackPreservesBootAndPrivateVNICClassifications|NamedHostRequiresExactRunningPrivateInstance|VolumeAttachmentLookupKeepsExactFilter|VolumeBackupPaginationKeepsNewestBoundedHistory)$'
ROOTS=['TestSDKSocketLaunchPreservesSignedProfileAndResponse','TestSDKSocketLaunchRejectsInexactSizingBeforeAnyRequest','TestSDKSocketManagedReadbackPreservesBootAndPrivateVNICClassifications','TestSDKSocketNamedHostRequiresExactRunningPrivateInstance','TestSDKSocketVolumeAttachmentLookupKeepsExactFilter','TestSDKSocketVolumeBackupPaginationKeepsNewestBoundedHistory']
EXPECTED=ROOTS+[ROOTS[2]+'/'+leaf for leaf in ['image','instance_without_image','size','tier']]
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def write(name,data): (OUT/name).write_text(json.dumps(data,indent=2)+'\n')
def git(*args): return subprocess.check_output(['git',*args],cwd=SOURCE,text=True).strip()
def snapshot():
    manifest=[]
    for rec in subprocess.check_output(['git','ls-files','--stage','-z'],cwd=SOURCE).split(b'\0'):
        if not rec:continue
        meta,path=rec.split(b'\t',1);mode,blob,stage=meta.decode().split();assert stage=='0'
        p=SOURCE/path.decode();data=os.readlink(p).encode() if mode=='120000' else p.read_bytes()
        manifest.append({'path':path.decode(),'mode':mode,'blob':blob,'sha256':hashlib.sha256(data).hexdigest()})
    return {'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain=v1','--untracked-files=all'),'tracked_count':len(manifest),'tracked_bytes_manifest_sha256':hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest(),'new_test_sha256':sha(SOURCE/'internal/oci/sdk_socket_boundary_integration_test.go')}
def group_members(pgid):
    found=[]
    for p in pathlib.Path('/proc').glob('[0-9]*/stat'):
        try:
            fields=p.read_text().rsplit(')',1)[1].split()
            if int(fields[2])==pgid:found.append({'pid':int(p.parent.name),'state':fields[0]})
        except (OSError,ValueError,IndexError):pass
    return found
def stage(name,argv):
    before=snapshot();assert before['head']==HEAD and before['tree']==TREE and not before['status']
    result={'owner':'/root/qa_integrator/artifact_tests','stage':name,'argv':argv,'env':ENV,'source_before':before,'default_vet':True,'default_tags':True,'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    write(name+'-started.json',result)
    clock=time.monotonic()
    with (OUT/(name+'.stdout')).open('xb') as stdout,(OUT/(name+'.stderr')).open('xb') as stderr:
        proc=subprocess.Popen(argv,cwd=SOURCE,env=ENV,stdout=stdout,stderr=stderr,start_new_session=True)
        result['pid']=proc.pid;write(name+'-running.json',result)
        print(json.dumps({'stage':name,'pid':proc.pid,'handle':str(OUT)}),flush=True)
        proc.wait()
    result.update(exit_code=proc.returncode,elapsed_seconds=time.monotonic()-clock,finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
    result['cleanup_before']=group_members(proc.pid)
    if any(p['state']!='Z' for p in result['cleanup_before']):
        os.killpg(proc.pid,signal.SIGTERM);deadline=time.monotonic()+5
        while time.monotonic()<deadline and any(p['state']!='Z' for p in group_members(proc.pid)):time.sleep(.1)
        if any(p['state']!='Z' for p in group_members(proc.pid)):os.killpg(proc.pid,signal.SIGKILL)
    result['cleanup_after']=group_members(proc.pid)
    result['cleanup_joined']=not any(p['state']!='Z' for p in result['cleanup_after'])
    result['source_after']=snapshot();result['source_unchanged']=result['source_after']==before
    result['raw_sha256']={name+'.stdout':sha(OUT/(name+'.stdout')),name+'.stderr':sha(OUT/(name+'.stderr'))}
    if name=='compile' and (OUT/'oci.test').exists():
        binary=OUT/'oci.test';os.chmod(binary,0o600)
        result['external_binary']={'path':str(binary),'mode':oct(binary.stat().st_mode&0o777),'bytes':binary.stat().st_size,'sha256':sha(binary),'elf':binary.read_bytes()[:4]==b'\x7fELF','never_executed':True}
    write(name+'-result.json',result)
    return result
result={'owner':'/root/qa_integrator/artifact_tests','head':HEAD,'tree':TREE,'source':str(SOURCE),'lock':LOCK,'wrapper_pid':os.getpid(),'attempt':1,'originals_removed':0,'adoption':False,'existing_terminal_and_14_fixture_outcomes_reused':True}
with open(LOCK,'a+') as lock:
    try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        result.update(state='LOCK_BUSY_NOT_LAUNCHED',lock_acquired=False);write('result.json',result);raise SystemExit(73)
    result['lock_acquired']=True;write('started.json',result)
    try:
        compile_argv=['nice','-n','19','timeout','--signal=TERM','--kill-after=5s','240s',GO,'test','-c','-mod=readonly','-p=1','-o',str(OUT/'oci.test'),'./internal/oci']
        compile_result=stage('compile',compile_argv);result['compile']=compile_result
        if compile_result['exit_code']==0 and compile_result['source_unchanged'] and compile_result['cleanup_joined'] and compile_result.get('external_binary',{}).get('elf'):
            runtime_argv=['nice','-n','19','timeout','--signal=TERM','--kill-after=5s','180s',GO,'test','-json','-mod=readonly','-p=1','-count=1','-parallel=1','-timeout=90s','-run',SELECTOR,'./internal/oci']
            runtime_result=stage('runtime',runtime_argv)
            events=[];malformed=[]
            for number,line in enumerate((OUT/'runtime.stdout').read_text().splitlines(),1):
                try:events.append(json.loads(line))
                except json.JSONDecodeError:malformed.append(number)
            terminal=[e for e in events if e.get('Action') in ('pass','fail','skip') and 'Test' in e]
            package=[e for e in events if e.get('Action') in ('pass','fail','skip') and 'Test' not in e]
            runtime_result.update(expected_tests=EXPECTED,test_outcomes=terminal,package_outcomes=package,malformed_json_lines=malformed)
            runtime_result['qualified']=runtime_result['exit_code']==0 and runtime_result['source_unchanged'] and runtime_result['cleanup_joined'] and not malformed and sorted(e['Test'] for e in terminal)==sorted(EXPECTED) and all(e['Action']=='pass' for e in terminal) and len(package)==1 and package[0]['Action']=='pass'
            write('runtime-result.json',runtime_result);result['runtime']=runtime_result
            result['state']='PASS' if runtime_result['qualified'] else 'NOT_QUALIFIED'
        else:result['state']='COMPILE_NOT_QUALIFIED_RUNTIME_NOT_LAUNCHED'
    except Exception as error:
        result['state']='RUNNER_ERROR';result['error']=repr(error)
    finally:
        fcntl.flock(lock,fcntl.LOCK_UN);result['lock_released']=True
        write('result.json',result)
print(json.dumps(result,indent=2),flush=True)
raise SystemExit(0 if result['state']=='PASS' else 1)
