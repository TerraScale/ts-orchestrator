#!/home/mariogk/.local/share/mise/installs/python/3.15.0/bin/python3.15
import datetime, fcntl, hashlib, json, os, pathlib, signal, subprocess, sys, time
config_path=pathlib.Path(__file__).with_name('request.json')
cfg=json.loads(config_path.read_text())
out=pathlib.Path(cfg['output']); root=pathlib.Path(cfg['workspace'])
result={'state':'STARTING','head':cfg['head'],'tree':cfg['tree'],'request_sha256':hashlib.sha256(config_path.read_bytes()).hexdigest(),'wrapper_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),'runs':[], 'execution_scope':cfg['execution_scope']}
active=None
lock_file=None
def save():
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
def pin():
    def git(*args): return subprocess.check_output(['/run/current-system/sw/bin/git',*args],cwd=root,text=True).strip()
    actual={'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain')}
    if actual!={'head':cfg['head'],'tree':cfg['tree'],'status':''}: raise RuntimeError('source identity/cleanliness mismatch: '+repr(actual))
    freeze=pathlib.Path(cfg['freeze'])
    if hashlib.sha256(freeze.read_bytes()).hexdigest()!=cfg['freeze_sha256']: raise RuntimeError('freeze hash mismatch')
    for tool,expected in cfg['tool_sha256'].items():
        if hashlib.sha256(pathlib.Path(tool).read_bytes()).hexdigest()!=expected: raise RuntimeError('pinned tool hash mismatch')
    return actual
def resources():
    available=next(int(line.split()[1])*1024 for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))
    load=os.getloadavg()[0]; compilers=0
    for proc in pathlib.Path('/proc').iterdir():
        if not proc.name.isdigit(): continue
        try:
            if (proc/'comm').read_text().strip()=='compile': compilers+=1
        except (OSError,UnicodeError): pass
    facts={'available_bytes':available,'load1':load,'go_compilers':compilers,'time':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if available<16*(1<<30) or load>=12 or compilers>4: raise RuntimeError('resource preflight refused: '+repr(facts))
    return facts
def reap_group(proc):
    try: os.killpg(proc.pid,signal.SIGTERM)
    except ProcessLookupError: return
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        try: os.killpg(proc.pid,0)
        except ProcessLookupError: return
        time.sleep(.1)
    try: os.killpg(proc.pid,signal.SIGKILL)
    except ProcessLookupError: pass

def run(kind,item,timeout_seconds):
    global active
    facts=resources(); identity=pin()
    command=['/run/current-system/sw/bin/nice','-n','19',cfg['go'],'test']
    if kind!='compile': raise RuntimeError('only true compilation is authorized by this wrapper')
    if item['package']!='./internal/bootstrapstart/materialsource' or item['tags'] not in [[],['fixturetest']]:
        raise RuntimeError('unexpected compile target or build tags')
    command += ['-c','-p=1','-mod=readonly']
    if item['tags']: command += ['-tags='+','.join(item['tags'])]
    command += ['-o',str(out/(item['name']+'.test')),item['package']]
    entry={'kind':kind,'name':item['name'],'tags':item['tags'],'package':item['package'],'command':command,'env':cfg['env'],'resources':facts,'identity':identity,'timeout_seconds':timeout_seconds,'started':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    result['runs'].append(entry); save()
    log=out/(kind+'-'+item['name']+'.log')
    with log.open('wb') as stream:
        active=subprocess.Popen(command,cwd=root,env=cfg['env'],stdout=stream,stderr=subprocess.STDOUT,start_new_session=True)
        entry['pid']=active.pid; entry['process_group']=active.pid; save()
        try: entry['exit_code']=active.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            entry['timed_out']=True
            os.killpg(active.pid,signal.SIGTERM)
            try: entry['exit_code']=active.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(active.pid,signal.SIGKILL); entry['exit_code']=active.wait()
        finally:
            reap_group(active); active=None
    entry['finished']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    entry['log']=str(log); entry['log_sha256']=hashlib.sha256(log.read_bytes()).hexdigest()
    binary=out/(item['name']+'.test')
    if binary.exists():
        binary.chmod(0o600)
        entry['binary']={'path':str(binary),'mode':oct(binary.stat().st_mode&0o777),'sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'executed':False}
    entry['process_group_after_terminal']='ABSENT'
    try: os.killpg(entry['process_group'],0)
    except ProcessLookupError: pass
    else: raise RuntimeError('compiler process group still present')
    if binary.exists() and binary.read_bytes()[:4]!=b'\x7fELF': raise RuntimeError('compile output is not ELF')
    save()
    if entry['exit_code']!=0 or entry.get('timed_out'): raise RuntimeError(kind+' failed: '+item['package'])
    if kind=='compile' and not binary.exists(): raise RuntimeError('compiler did not produce binary')

try:
    result['pre_identity']=pin(); result['pre_resources']=resources()
    lock_file=open(cfg['lock'],'a+')
    fcntl.flock(lock_file,fcntl.LOCK_EX|fcntl.LOCK_NB)
    result['state']='RUNNING'; save()
    for item in cfg['packages']: run('compile',item,cfg['compile_timeout'])
    result['state']='PASS'
except BaseException as error:
    result['state']='FAILED'; result['error']=repr(error)
finally:
    if active is not None:
        reap_group(active)
        try: active.wait(timeout=5)
        except subprocess.TimeoutExpired: pass
    try: result['post_identity']=pin()
    except BaseException as error:
        result['state']='FAILED'; result['post_identity_error']=repr(error)
    if lock_file is not None:
        fcntl.flock(lock_file,fcntl.LOCK_UN); lock_file.close()
    result['lock_released']=True; save()
print(json.dumps({'state':result['state'],'output':str(out),'error':result.get('error'),'runs':len(result['runs'])}),flush=True)
sys.exit(0 if result['state']=='PASS' else 1)
