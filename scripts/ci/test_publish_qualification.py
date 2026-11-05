#!/usr/bin/env python3
"""Exercise atomic release visibility through the real publication script."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('publish-qualification.sh')
TOOL = r'''
import base64,json,os,pathlib,sys
state_file=pathlib.Path(os.environ['PUBLICATION_STATE'])
s=json.loads(state_file.read_text());a=sys.argv[1:]
def save():state_file.write_text(json.dumps(s))
if pathlib.Path(sys.argv[0]).name=='go':print('go1.27.3');raise SystemExit()
if a[:2]==['release','view']:
 if not s['exists']:raise SystemExit(1)
 print(json.dumps(dict(tagName=s['tag'],targetCommitish=os.environ['GITHUB_SHA'],isDraft=s['draft'],isPrerelease=True,assets=[{'name':n} for n in s['assets']])))
elif a[:2]==['release','create']:
 assert '--draft' in a
 s.update(exists=True,draft=True,tag=a[2]);s['events'].append('create-draft');save()
elif a[:2]==['release','upload']:
 name=pathlib.Path(a[3]).name
 assert s['draft'], 'upload exposed an incomplete public release'
 if name==s.get('fail'):raise SystemExit(1)
 s['assets'][name]=base64.b64encode(pathlib.Path(a[3]).read_bytes()).decode();s['events'].append('upload:'+name);save()
elif a[:2]==['release','download']:
 name=a[a.index('--pattern')+1];out=pathlib.Path(a[a.index('--output')+1]);out.write_bytes(base64.b64decode(s['assets'][name]));s['events'].append('readback:'+name);save()
elif a[:2]==['release','edit']:
 assert '--draft=false' in a
 assert len(s['assets'])==5 and 'qualification.json' in s['assets']
 assert all('readback:'+n in s['events'] for n in s['assets'])
 s['draft']=False;s['events'].append('publish');save()
elif a[0]=='api':
 assert not s['draft'], 'unpublished tag queried before completion'
 print(os.environ['GITHUB_SHA'])
else:raise AssertionError(a)
'''


class AtomicPublication(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts/ci').mkdir(parents=True)
        (self.root / 'scripts/ci/publish-qualification.sh').write_text(SCRIPT.read_text())
        (self.root / 'dist').mkdir()
        for arch in ('amd64', 'arm64'):
            (self.root / f'dist/terrascale-orchestrator-linux-{arch}').write_bytes(arch.encode())
        for file in ('go.mod', 'go.sum'):
            (self.root / file).write_text('fixture\n')
        for command in (['init','-q'], ['-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','source','--allow-empty']):
            subprocess.run(['git',*command],cwd=self.root,check=True)
        sha = subprocess.check_output(['git','rev-parse','HEAD'],cwd=self.root,text=True).strip()
        tools = self.root / 'tools'
        tools.mkdir()
        for name in ('gh','go'):
            path = tools / name
            path.write_text('#!'+sys.executable+'\n'+TOOL)
            path.chmod(0o700)
        self.state = self.root / 'state.json'
        self.state.write_text(json.dumps(dict(exists=False,draft=True,assets={},events=[])))
        self.env = os.environ | dict(PATH=str(tools)+os.pathsep+os.environ['PATH'],PUBLICATION_STATE=str(self.state),GITHUB_SHA=sha,GITHUB_RUN_ID='123',GITHUB_RUN_NUMBER='456',GH_TOKEN='fixture')

    def run_publisher(self):
        return subprocess.run(['bash','scripts/ci/publish-qualification.sh'],cwd=self.root,env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)

    def test_five_complete_publications_become_visible_only_after_all_readbacks(self):
        for _ in range(5):
            self.state.write_text(json.dumps(dict(exists=False,draft=True,assets={},events=[])))
            result = self.run_publisher()
            self.assertEqual(result.returncode,0,result.stderr)
            state = json.loads(self.state.read_text())
            self.assertFalse(state['draft'])
            self.assertEqual(state['events'][-1],'publish')
            self.assertEqual(len(state['assets']),5)

    def test_partial_upload_stays_private_and_retry_finishes_before_publication(self):
        state = json.loads(self.state.read_text())
        state['fail'] = 'terrascale-d15-qualify'
        self.state.write_text(json.dumps(state))
        self.assertNotEqual(self.run_publisher().returncode,0)
        state = json.loads(self.state.read_text())
        self.assertTrue(state['draft'])
        self.assertNotIn('publish',state['events'])
        state.pop('fail')
        self.state.write_text(json.dumps(state))
        result = self.run_publisher()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads(self.state.read_text())['events'][-1],'publish')


if __name__=='__main__':
    unittest.main()
