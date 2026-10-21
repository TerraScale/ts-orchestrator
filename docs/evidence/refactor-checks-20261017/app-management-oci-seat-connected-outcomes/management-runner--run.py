import collections, fcntl, hashlib, json, os, pathlib, resource, subprocess, time
OUT=pathlib.Path(__file__).parent
REQUEST=pathlib.Path('/tmp/ts-management-observation-2d158-120-source-fd67jiak/request.json')
EXPECTED_REQUEST_SHA='6622dcff83909fd593f1e810cc7f2c28a55a33edf26037d37282c511d742362c'
def sha(b):return hashlib.sha256(b).hexdigest()
def write(name,value):
    with (OUT/name).open('x') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
def git(*a):return subprocess.check_output(['/run/current-system/sw/bin/git','-C',str(W),*a],env=CHILD_ENV)
raw=REQUEST.read_bytes()
assert sha(raw)==EXPECTED_REQUEST_SHA
request=json.loads(raw)
CHILD_ENV=request['request']['effective_child_environment']
assert dict(os.environ)==CHILD_ENV,'actual wrapper environment must equal exact six keys'
W=pathlib.Path(request['worktree'])
SOURCE=REQUEST.parent
for name,digest in request['pins'].items():assert sha((SOURCE/name).read_bytes())==digest,name
seal=json.loads((SOURCE/'seal.json').read_bytes())
assert sha(pathlib.Path(__file__).read_bytes())==seal['wrapper_sha256']
manifest=json.loads((SOURCE/'tracked-source-manifest.json').read_bytes())
tool_pins=json.loads((SOURCE/'tool-pins.json').read_bytes())
def snapshot():
    for tool in tool_pins:
        p=pathlib.Path(tool['path'])
        assert str(p.resolve())==tool['resolved'] and sha(p.read_bytes())==tool['sha256'],tool['path']
    current=[]
    for record in git('ls-files','--stage','-z').split(b'\0'):
        if not record:continue
        meta,rawpath=record.split(b'\t',1)
        mode,blob,stage=meta.decode().split();assert stage=='0'
        path=rawpath.decode();p=W/path
        data=os.readlink(p).encode() if mode=='120000' else p.read_bytes()
        current.append({'path':path,'mode':mode,'git_blob':blob,'bytes':len(data),'sha256':sha(data)})
    assert current==manifest['entries'],'full tracked source drift'
    return {'head':git('rev-parse','HEAD').decode().strip(),'tree':git('rev-parse','HEAD^{tree}').decode().strip(),'status':git('status','--porcelain=v1','--untracked-files=all').decode(),'tracked_count':len(current),'tracked_manifest_sha256':sha((SOURCE/'tracked-source-manifest.json').read_bytes()),'request_sha256':sha(REQUEST.read_bytes()),'wrapper_sha256':sha(pathlib.Path(__file__).read_bytes()),'tool_pins_sha256':sha((SOURCE/'tool-pins.json').read_bytes())}
assert not (OUT/'started.json').exists() and not (OUT/'receipt.json').exists(),'one attempt only'
with open(request['request']['shared_lock'],'a') as gate:
    try:fcntl.flock(gate,fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError:
        write('receipt.json',{'state':'LOCK_BUSY_NOT_LAUNCHED','request_sha256':EXPECTED_REQUEST_SHA});raise SystemExit(75)
    pre=snapshot()
    assert pre['head']==request['commit'] and pre['tree']==request['tree'] and not pre['status']
    write('preflight.json',{'source':pre,'argv':request['request']['argv'],'effective_child_environment':request['request']['effective_child_environment'],'GOROOT_present':False,'default_vet':True})
    started=time.time();clock=time.monotonic()
    with (OUT/'stdout.jsonl').open('xb') as stdout,(OUT/'stderr.log').open('xb') as stderr:
        proc=subprocess.Popen(request['request']['argv'],cwd=W,stdout=stdout,stderr=stderr,start_new_session=True,env=CHILD_ENV)
        write('started.json',{'pid':proc.pid,'epoch':started,'argv':request['request']['argv']})
        print(json.dumps({'state':'STARTED','pid':proc.pid,'output':str(OUT)}),flush=True)
        returncode=proc.wait()
    elapsed=time.monotonic()-clock
    post=snapshot();actions=[];packages=[];malformed=[]
    for number,line in enumerate((OUT/'stdout.jsonl').read_text().splitlines(),1):
        try:
            event=json.loads(line)
            if not isinstance(event,dict):raise ValueError('event must be a JSON object')
        except (json.JSONDecodeError,ValueError) as error:
            malformed.append({'line':number,'raw':line,'error':str(error)});continue
        if event.get('Action') in ['pass','fail','skip']:
            if event.get('Test'):actions.append({k:event[k] for k in ['Test','Action','Elapsed','Package'] if k in event})
            else:packages.append(event)
    actual=collections.Counter(e['Test'] for e in actions)
    expected=collections.Counter(request['expected_pass_tests'])
    success=returncode==0 and not malformed and len(actions)==request['expected_terminal_outcomes'] and actual==expected and all(e['Action']=='pass' and e.get('Package')==request['expected_package'] for e in actions) and len(packages)==1 and packages[0]['Action']=='pass' and packages[0].get('Package')==request['expected_package'] and pre==post
    receipt={'state':'PASS' if success else 'NOT_QUALIFIED','exit_code':returncode,'wall_seconds':elapsed,'max_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'source_pre':pre,'source_post':post,'expected_tests':request['expected_pass_tests'],'expected_package':request['expected_package'],'actual_name_counts':dict(actual),'malformed_json_lines':malformed,'test_outcomes':actions,'package_outcomes':packages,'stdout_sha256':sha((OUT/'stdout.jsonl').read_bytes()),'stderr_sha256':sha((OUT/'stderr.log').read_bytes()),'scope':'one exact selected root attempt; no live OCI/native/containerd/fullAPP qualification'}
    write('receipt.json',receipt)
    with (OUT/'RESULT-SHA256SUMS').open('x') as f:
        for p in sorted(OUT.iterdir()):
            if p.name!='RESULT-SHA256SUMS' and p.is_file():f.write(sha(p.read_bytes())+'  '+p.name+'\n')
    print(json.dumps(receipt),flush=True)
raise SystemExit(0 if success else 1)
