import pathlib, subprocess, json, os, time, fcntl, datetime, hashlib
root=pathlib.Path('/tmp/ts-terminal-b8fee-runtime-artifact-tests')
source='/tmp/ts-terminal-sdk-boundary-7cswu3af/source'
lock='/tmp/ts-orch-refactor-general-check.lock'
env={'HOME':'/home/mariogk','PATH':'/home/mariogk/.local/share/mise/installs/go/1.27.1/bin:/run/current-system/sw/bin','LANG':'C.UTF-8','GOMAXPROCS':'2','GOFLAGS':'-p=2','GOTOOLCHAIN':'local'}
argv=['nice','-n','19','timeout','--signal=TERM','--kill-after=5s','120s','/home/mariogk/.local/share/mise/installs/go/1.27.1/bin/go','test','-json','-mod=readonly','-p=1','-count=1','-parallel=1','-timeout=60s','-run','^TestTerminalSDKDeleteSocketBoundary$','./internal/oci']
def git(*args):
    return subprocess.check_output(['git',*args],cwd=source,text=True).strip()
def snapshot():
    return {'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain=v1'),'test_sha256':hashlib.sha256((pathlib.Path(source)/'internal/oci/terminal_sdk_boundary_integration_test.go').read_bytes()).hexdigest()}
result={'owner':'/root/qa_integrator/artifact_tests','pid':os.getpid(),'source':source,'argv':argv,'env':env,'lock':lock,'default_vet':True,'default_tags':True,'selector':'^TestTerminalSDKDeleteSocketBoundary$'}
lockfile=open(lock,'a+')
try:
    fcntl.flock(lockfile,fcntl.LOCK_EX|fcntl.LOCK_NB)
except BlockingIOError:
    result.update(lock_acquired=False,runtime_executed=False)
    (root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    raise SystemExit(73)
result.update(lock_acquired=True,source_before=snapshot(),started_at=datetime.datetime.now(datetime.timezone.utc).isoformat())
if result['source_before']['head']!='b8fee5fcdcae1de49fc36313869ed332e66f00f6' or result['source_before']['status']:
    raise RuntimeError('source changed before runtime')
(root/'started.json').write_text(json.dumps(result,indent=2)+'\n')
start=time.monotonic()
with (root/'raw.jsonl').open('wb') as stdout, (root/'raw.stderr').open('wb') as stderr:
    completed=subprocess.run(argv,cwd=source,env=env,stdout=stdout,stderr=stderr,start_new_session=True)
result.update(exit_code=completed.returncode,elapsed_seconds=time.monotonic()-start,runtime_executed=True,finished_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_after=snapshot())
result['raw_sha256']={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ['raw.jsonl','raw.stderr']}
fcntl.flock(lockfile,fcntl.LOCK_UN)
lockfile.close()
result['lock_released']=True
(root/'result.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
raise SystemExit(completed.returncode)
