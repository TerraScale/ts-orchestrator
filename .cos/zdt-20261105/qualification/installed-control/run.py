from pathlib import Path
import subprocess,json,zlib,os,shlex,hashlib
root=Path('/home/mariogk/.t3/worktrees/ts-orchestrator/t3-fe58d36d')
base='2142b1f308b1c1169d25093f93eab3b10c479e1c'
payload={f'internal/{pkg}/zdt_installed_control_qualification_test.go':(root/f'.cos/zdt-20261105/qualification/installed-control/{name}_test.go.txt').read_text() for pkg,name in [('app','service'),('edge','edge')]}
mesh=subprocess.check_output(['git','show',base+':internal/natscell/mesh/mesh_integration_test.go'],cwd=root,text=True)
old='printApply(&out)(send(t.Context(), gru.conn, ApplyRequest{Name: "whoami", Entry: Entry{Generation: time.Now().UnixNano()}}, 5*time.Second))'
assert old in mesh
payload['internal/natscell/mesh/mesh_integration_test.go']=mesh.replace(old,'Remove(t.Context(), gru.conn, "whoami", &out)')
transport=Path('/tmp/zdt-installed-control.json.zlib');transport.write_bytes(zlib.compress(json.dumps(payload).encode()));transport.chmod(0o600)
for host in ['delta','mariogk-dev']:
 subprocess.run(['scp','-q','-o','BatchMode=yes','-o','ConnectTimeout=5',str(transport),host+':'+str(transport)],timeout=15,check=False)
script="set -euo pipefail\npython3 - <<'PROOF'\nfrom pathlib import Path\nimport json,zlib\nfor f,s in json.loads(zlib.decompress(Path('/tmp/zdt-installed-control.json.zlib').read_bytes())).items():\n Path(f).write_text(s)\nPROOF\nmise exec -- go test -v -count=1 -timeout 90s ./internal/app -run '^TestInstalledColdServiceCLI$'\nmise exec -- go test -v -count=1 -timeout 30s ./internal/edge -run '^TestInstalledColdLastNodeCannotStop$'\nmise exec -- go test -v -count=1 -timeout 100s ./internal/natscell/mesh -run '^TestMeshAppliesInEveryRegionAndCatchesUpAfterRestart$'"
raise SystemExit(subprocess.run(['/home/mariogk/.local/bin/ts-heavy-any','bash','-lc',script,'--repo','ts-orchestrator','--branch',base],cwd=root,env=dict(os.environ,TS_HEAVY_PARTITION='zdt-installed-control',TS_SLOT_LABEL='test-slow')).returncode)
