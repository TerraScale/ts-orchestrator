import collections,contextlib,fcntl,hashlib,json,os,pathlib,resource,subprocess,sys,time
OUT=pathlib.Path(__file__).parent
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
assert sha(OUT/'request.json')==sys.argv[1] and sha(__file__)==sys.argv[2]
m=json.loads((OUT/'request.json').read_text());w=pathlib.Path(m['worktree']);manifest=pathlib.Path(m['source_manifest'])
assert sha(manifest)==m['source_manifest_sha256'] and sha(OUT/'static-review.json')==m['static_review_sha256']
assert sha(OUT/'static-import-closure.json')==m['static_closure_sha256']
CHILD_ENV=m['request']['effective_child_environment']
assert dict(os.environ)==CHILD_ENV,'wrapper environment must equal exact six keys'
sources=json.loads(manifest.read_text())
def write(name,value):
 with (OUT/name).open('x') as f:json.dump(value,f,indent=2);f.write('\n')
def git(*a):return subprocess.check_output(['/run/current-system/sw/bin/git','-C',str(w),*a],env=CHILD_ENV).decode().strip()
def snapshot():
 return {'head':git('rev-parse','HEAD'),'tree':git('rev-parse','HEAD^{tree}'),'status':git('status','--porcelain'),'files':{p:sha(w/p) for p in sources['files']},'tools':{p:sha(p) for p in m['tool_sha256']},'request_sha256':sha(OUT/'request.json'),'wrapper_sha256':sha(__file__),'manifest_sha256':sha(manifest)}
pre=snapshot();assert pre['head']==m['commit'] and pre['tree']==m['tree'] and not pre['status'];assert pre['files']==sources['files'] and pre['tools']==m['tool_sha256']
assert pre['tools']['/home/mariogk/.local/share/mise/installs/go/1.27.1/bin/go']==m['go_binary_sha256']
assert __import__('os').geteuid()==1000
write('preflight.json',{'source':pre,'argv':m['request']['argv'],'cwd':str(w),'compile_only':False,'selected_test':True})
with contextlib.ExitStack() as locks:
 for lock in m['request']['locks']:
  handle=locks.enter_context(open(lock,'a'))
  try:fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:write('receipt.json',{'state':'LOCK_BUSY_NOT_LAUNCHED','lock':lock});raise SystemExit(75)
 start=time.monotonic()
 with (OUT/'runtime.stdout').open('xb') as stdout,(OUT/'runtime.stderr').open('xb') as stderr:
  proc=subprocess.Popen(m['request']['argv'],cwd=w,stdout=stdout,stderr=stderr,start_new_session=True,env=CHILD_ENV)
  write('started.json',{'pid':proc.pid,'argv':m['request']['argv'],'epoch':time.time()});print(json.dumps({'state':'STARTED_FOCUSED_REGRESSION','pid':proc.pid,'output':str(OUT)}),flush=True);rc=proc.wait()
 post=snapshot();actions=[];packages=[];malformed=[];runs=[];starts=[];scope_errors=[]
 for number,line in enumerate((OUT/'runtime.stdout').read_text().splitlines(),1):
  try:
   event=json.loads(line)
   if not isinstance(event,dict):raise ValueError('event must be a JSON object')
   if event.get('Package')!=m['expected_package']:scope_errors.append({'line':number,'reason':'unexpected package','event':event})
   if event.get('Test') and event['Test'] not in m['expected_pass_tests']:scope_errors.append({'line':number,'reason':'unexpected test','event':event})
   if event.get('Action') not in ['start','run','output','pass','fail','skip']:scope_errors.append({'line':number,'reason':'unexpected action','event':event})
   if event.get('Action')=='run':runs.append(event.get('Test'))
   if event.get('Action')=='start':starts.append(event.get('Package'))
  except (json.JSONDecodeError,ValueError) as error:
   malformed.append({'line':number,'error':str(error)});continue
  if event.get('Action') in ['pass','fail','skip']:
   if event.get('Test'):actions.append({k:event[k] for k in ['Test','Action','Elapsed','Package'] if k in event})
   else:packages.append(event)
 actual=collections.Counter(e['Test'] for e in actions);expected=collections.Counter(m['expected_pass_tests'])
 success=rc==0 and pre==post and not malformed and not scope_errors and collections.Counter(runs)==expected and starts==[m['expected_package']] and len(actions)==m['expected_terminal_outcomes'] and actual==expected and all(e['Action']=='pass' and e.get('Package')==m['expected_package'] for e in actions) and len(packages)==1 and packages[0]['Action']=='pass' and packages[0].get('Package')==m['expected_package']
 receipt={'state':'FOCUSED_REGRESSION_PASS' if success else 'NOT_QUALIFIED','exit_code':rc,'wall_seconds':time.monotonic()-start,'max_child_rss_kib':resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,'source_unchanged':pre==post,'expected_tests':m['expected_pass_tests'],'expected_package':m['expected_package'],'actual_name_counts':dict(actual),'malformed_json_lines':malformed,'scope_errors':scope_errors,'run_name_counts':dict(collections.Counter(runs)),'package_starts':starts,'test_outcomes':actions,'package_outcomes':packages,'stdout_sha256':sha(OUT/'runtime.stdout'),'stderr_sha256':sha(OUT/'runtime.stderr'),'scope':m['request']['scope']}
 write('postflight.json',post);write('receipt.json',receipt);print(json.dumps(receipt),flush=True)
raise SystemExit(0 if success else 1)
