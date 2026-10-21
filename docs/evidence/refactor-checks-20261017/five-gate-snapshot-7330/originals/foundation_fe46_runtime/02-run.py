#!/home/mariogk/.local/share/mise/installs/python/3.15.0/bin/python3.15
import collections, datetime, stat, fcntl, hashlib, json, os, pathlib, signal, subprocess, sys, time
def unique_pairs(pairs):
    value={}
    for key,item in pairs:
        if key in value: raise ValueError('duplicate JSON object key: '+key)
        value[key]=item
    return value
def invalid_constant(value):
    raise ValueError('nonfinite JSON constant: '+value)
def strict_json_loads(value):
    return json.loads(value,object_pairs_hook=unique_pairs,parse_constant=invalid_constant)
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
    if manifest.get('head')!=cfg['head'] or manifest.get('tree')!=cfg['tree'] or manifest.get('worktree')!=str(root) or manifest.get('status')!='':
        raise RuntimeError('manifest identity/cleanliness mismatch')
    entries=manifest.get('files')
    if not isinstance(entries,dict) or len(entries)!=cfg['manifest_validation_contract']['entries']:
        raise RuntimeError('manifest source entry inventory mismatch')
    tree_wire=subprocess.check_output(['/run/current-system/sw/bin/git','ls-tree','-z',cfg['head'],'--',*entries],cwd=root)
    modes={}
    for wire in tree_wire.split(b'\0'):
        if not wire: continue
        attributes,name=wire.decode('utf-8').split('\t',1)
        mode,kind,blob=attributes.split()
        if name in modes or kind!='blob' or mode!='100644': raise RuntimeError('unexpected manifest Git mode/type/duplicate: '+name)
        modes[name]=int(mode,8)&0o777
    if set(modes)!=set(entries): raise RuntimeError('manifest entries differ from exact pinned Git tree paths')
    for name,expected in entries.items():
        relative=pathlib.PurePosixPath(name)
        if relative.is_absolute() or '..' in relative.parts: raise RuntimeError('manifest path escapes source workspace')
        path=root/name
        attributes=path.lstat()
        if not stat.S_ISREG(attributes.st_mode) or stat.S_IMODE(attributes.st_mode)!=modes[name]:
            raise RuntimeError('manifest actual source mode/type mismatch: '+name)
        if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
            raise RuntimeError('manifest actual source SHA256 mismatch: '+name)
    actual['manifest_validation']={'entries':len(entries),'sha256':cfg['freeze_sha256'],'source_sha256_verified':True,'regular_file_modes_verified_against_pinned_git_tree':True}
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
    if kind!='runtime': raise RuntimeError('this wrapper authorizes runtime selectors only')
    command += ['-json','-p=1','-parallel=1','-mod=readonly','-count=1','-timeout=120s']
    if item['tags']: command += ['-tags='+','.join(item['tags'])]
    command += ['-run',item['run'],item['package']]
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
    entry['process_group_after_terminal']='ABSENT'
    try: os.killpg(entry['process_group'],0)
    except ProcessLookupError: pass
    else: raise RuntimeError('runtime process group still present')
    save()
    if entry['exit_code']!=0 or entry.get('timed_out'): raise RuntimeError('runtime failed: '+item['name'])
    if kind=='runtime':
        events=[]; non_json=[]
        for line in log.read_text().splitlines():
            try:
                event=strict_json_loads(line)
                if not isinstance(event,dict): raise ValueError('runtime event is not a JSON object')
                events.append(event)
            except (ValueError,TypeError): non_json.append(line)
        test_runs=collections.Counter(e['Test'] for e in events if e.get('Test') and e.get('Action')=='run')
        test_pass=collections.Counter(e['Test'] for e in events if e.get('Test') and e.get('Action')=='pass')
        expected=collections.Counter({name:1 for name in item['expected_tests']})
        forbidden=[e for e in events if e.get('Action') in ['skip','fail']]
        package_pass=[e for e in events if e.get('Action')=='pass' and not e.get('Test')]
        entry['outcomes']={'expected':item['expected_tests'],'test_runs':dict(test_runs),'test_pass':dict(test_pass),'package_pass':len(package_pass),'forbidden':forbidden,'non_json':non_json}
        save()
        if test_runs!=expected or test_pass!=expected or len(package_pass)!=1 or forbidden or non_json: raise RuntimeError('runtime exact event inventory mismatch: '+item['package'])
try:
    result['pre_identity']=pin(); result['pre_resources']=resources()
    lock_file=open(cfg['lock'],'a+')
    fcntl.flock(lock_file,fcntl.LOCK_EX|fcntl.LOCK_NB)
    result['state']='RUNNING'; save()
    result['retained_compilations']=[]
    for retained in cfg['retained_compilations']:
        prior_path=pathlib.Path(retained['result'])
        if hashlib.sha256(prior_path.read_bytes()).hexdigest()!=retained['sha256']: raise RuntimeError('retained compile result hash mismatch')
        prior=strict_json_loads(prior_path.read_text())
        candidates=[item for item in prior['runs'] if item['kind']=='compile' and item['package']==retained['package'] and item.get('tags',[])==retained['tags']]
        if len(candidates)!=1 or candidates[0].get('exit_code')!=0: raise RuntimeError('retained compile missing exact package/tag PASS')
        artifact=candidates[0]['binary']
        if artifact['mode']!='0o600' or artifact['executed']: raise RuntimeError('retained artifact state mismatch')
        binary=pathlib.Path(artifact['path'])
        if binary.stat().st_mode&0o777!=0o600 or hashlib.sha256(binary.read_bytes()).hexdigest()!=artifact['sha256']: raise RuntimeError('retained artifact changed')
        result['retained_compilations'].append({'provenance':retained,'compiled_head':prior['head'],'compiled_tree':prior['tree'],'original_compile':candidates[0]})
    save()
    for item in cfg['packages']: run('runtime',item,cfg['runtime_outer_timeout'])
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
