#!/home/mariogk/.local/share/mise/installs/python/3.15.0/bin/python3.15
import collections, math, datetime, fcntl, hashlib, json, os, pathlib, signal, subprocess, sys, time
def unique_pairs(pairs):
    value={}
    for key,item in pairs:
        if key in value: raise ValueError('duplicate JSON object key: '+key)
        value[key]=item
    return value
def invalid_constant(value):
    raise ValueError('nonfinite JSON constant: '+value)
def finite_float(value):
    result=float(value)
    if not math.isfinite(result): raise ValueError('nonfinite JSON number: '+value)
    return result
def strict_json_loads(value):
    return json.loads(value,object_pairs_hook=unique_pairs,parse_constant=invalid_constant,parse_float=finite_float)
config_path=pathlib.Path(__file__).with_name('request.json')
cfg=strict_json_loads(config_path.read_text())
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
    manifest=strict_json_loads(freeze.read_text())
    for name,expected in manifest['source_files'].items():
        if hashlib.sha256((root/name).read_bytes()).hexdigest()!=expected: raise RuntimeError('full tracked source bytes mismatch: '+name)
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
def owned_group(proc):
    members=[]
    for path in pathlib.Path('/proc').glob('[0-9]*'):
        try:
            wire=(path/'stat').read_text(); fields=wire[wire.rfind(')')+2:].split()
            if int(fields[2])==proc.pid or int(path.name)==proc.pid: members.append(int(path.name))
        except (OSError,ValueError,IndexError): pass
    return members
def reap_group(proc):
    for sig in (signal.SIGTERM,signal.SIGKILL):
        proc.poll()
        if not owned_group(proc): break
        try: os.killpg(proc.pid,sig)
        except ProcessLookupError: pass
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            proc.poll()
            if not owned_group(proc): break
            time.sleep(.05)
    proc.poll()
    return owned_group(proc)
def interrupted(signum,frame):
    raise RuntimeError('runner interrupted by signal '+str(signum))
old_handlers={sig:signal.signal(sig,interrupted) for sig in (signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}

def run(kind,item,timeout_seconds):
    global active
    facts=resources(); identity=pin()
    command=['/run/current-system/sw/bin/nice','-n','19',cfg['go'],'test']
    if kind!='runtime': raise RuntimeError('only exact focused runtime is authorized by this wrapper')
    if item['package']!='./internal/natscell' or item['tags']!=[]:
        raise RuntimeError('unexpected compile target or build tags')
    command += ['-json','-count=1','-p=1','-parallel=1','-mod=readonly','-timeout='+cfg['test_timeout'],'-run',cfg['selector']]
    if item['tags']: command += ['-tags='+','.join(item['tags'])]
    command += [item['package']]
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
            remaining=reap_group(active)
            entry['remaining_group_processes']=remaining
            if remaining: raise RuntimeError('owned runtime group remains after cleanup')
            active=None
    entry['finished']=datetime.datetime.now(datetime.timezone.utc).isoformat()
    entry['log']=str(log); entry['log_sha256']=hashlib.sha256(log.read_bytes()).hexdigest()
    entry['process_group_after_terminal']='ABSENT'
    try: os.killpg(entry['process_group'],0)
    except ProcessLookupError: pass
    else: raise RuntimeError('compiler process group still present')
    save()
    if entry['exit_code']!=0 or entry.get('timed_out'): raise RuntimeError(kind+' failed: '+item['package'])
    events=[]; malformed=[]
    package='github.com/TerraScale/ts-orchestrator/internal/natscell'
    for index,line in enumerate(log.read_text().splitlines(),1):
        try:
            event=strict_json_loads(line)
            if not isinstance(event,dict) or not isinstance(event.get('Action'),str) or event.get('Package')!=package:
                raise ValueError('event shape or package identity mismatch')
            if 'Test' in event and (not isinstance(event['Test'],str) or not event['Test']):
                raise ValueError('invalid Test field')
            events.append(event)
        except (ValueError,TypeError): malformed.append(index)
    runs=collections.Counter(e['Test'] for e in events if e.get('Test') and e['Action']=='run')
    passed=collections.Counter(e['Test'] for e in events if e.get('Test') and e['Action']=='pass')
    names=set(cfg['expected_roots'])|set(cfg['expected_leaves'])
    expected=collections.Counter({name:1 for name in names})
    forbidden=[e for e in events if e['Action'] in ('skip','fail','build-fail') or e.get('Test') and e['Test'] not in names]
    package_pass=[e for e in events if e['Action']=='pass' and not e.get('Test')]
    package_start=[e for e in events if e['Action']=='start' and not e.get('Test')]
    entry['outcomes']={'expected':sorted(names),'test_runs':dict(runs),'test_pass':dict(passed),'package_pass':len(package_pass),'package_start':len(package_start),'forbidden':forbidden,'malformed_lines':malformed}; save()
    if runs!=expected or passed!=expected or len(package_pass)!=1 or len(package_start)!=1 or forbidden or malformed:
        raise RuntimeError('focused runtime exact event inventory mismatch')

try:
    result['pre_identity']=pin(); result['pre_resources']=resources()
    lock_file=open(cfg['lock'],'a+')
    fcntl.flock(lock_file,fcntl.LOCK_EX|fcntl.LOCK_NB)
    result['state']='RUNNING'; save()
    for item in cfg['packages']: run('runtime',item,cfg['runtime_timeout'])
    result['state']='PASS'
except BaseException as error:
    result['state']='FAILED'; result['error']=repr(error)
finally:
    for sig in old_handlers: signal.signal(sig,signal.SIG_IGN)
    remaining=[]
    if active is not None:
        try: remaining=reap_group(active)
        except BaseException as error:
            result['state']='FAILED'; result['cleanup_error']=repr(error); remaining=owned_group(active)
        if remaining:
            result['state']='FAILED'; result['cleanup_pending']={'remaining_group_processes':remaining,'lock_held':True}; save()
            print(json.dumps({'state':'FAILED_CLEANUP_PENDING','remaining_group_processes':remaining,'lock_held':True}),flush=True)
            while remaining:
                active.poll(); time.sleep(.05); remaining=owned_group(active)
        active.poll()
        result['cleanup_owned_group_after']='ABSENT'
    try: result['post_identity']=pin()
    except BaseException as error:
        result['state']='FAILED'; result['post_identity_error']=repr(error)
    if lock_file is not None:
        fcntl.flock(lock_file,fcntl.LOCK_UN); lock_file.close()
    result['lock_released']=True; save()
    for sig,handler in old_handlers.items(): signal.signal(sig,handler)

print(json.dumps({'state':result['state'],'output':str(out),'error':result.get('error'),'runs':len(result['runs'])}),flush=True)
sys.exit(0 if result['state']=='PASS' else 1)
