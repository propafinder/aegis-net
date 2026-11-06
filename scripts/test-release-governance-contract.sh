#!/usr/bin/env bash
# Offline metadata and actual workflow-freshness fixtures. No configured token.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
python3 - "${ROOT}" <<'PY'
import copy, importlib.util, os, subprocess, sys, time, tempfile
from pathlib import Path
root = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location('governance', root/'scripts/check-release-governance.py')
gate = importlib.util.module_from_spec(spec); spec.loader.exec_module(gate)
base = '/repos/fixture-owner/fixture-repo'; sha = 'a'*40
fixture = {
    base: {'full_name':'fixture-owner/fixture-repo','private':True,'default_branch':'main','archived':False,'disabled':False,'owner':{'type':'User'}},
    base+'/compare/'+sha+'...main': {'status':'identical','base_commit':{'sha':sha},'merge_base_commit':{'sha':sha}},
    base+'/branches/main/protection': {
        'enforce_admins':{'enabled':True},'allow_force_pushes':{'enabled':False},'allow_deletions':{'enabled':False},
        'required_pull_request_reviews': {'required_approving_review_count':1,'dismiss_stale_reviews':True,'require_code_owner_reviews':True,'require_last_push_approval':True},
        'required_status_checks':{'strict':True,'contexts':list(gate._ci.REQUIRED_JOBS)}},
    base+'/actions/secrets':{'total_count':0,'secrets':[]},
}
for env, secret in gate.ENVIRONMENTS.items():
    prefix=base+'/environments/'+env
    fixture[prefix]={'name':env,'can_admins_bypass':False,'protection_rules':[{'type':'required_reviewers','prevent_self_review':True,'reviewers':[{'type':'User','reviewer':{'id':42}}]}],
                     'deployment_branch_policy':{'protected_branches':False,'custom_branch_policies':True}}
    fixture[prefix+'/deployment-branch-policies']={'total_count':1,'branch_policies':[{'name':'main','type':'branch'}]}
    fixture[prefix+'/secrets']={'total_count':1,'secrets':[{'name':secret}]}
passed = 0
def check(data, expected=None, event='workflow_dispatch', ref='refs/heads/main'):
    global passed
    requests=[]
    def fetch(path, params=None):
        requests.append(path)
        if path not in data: raise gate.GateError('fixture_metadata_unavailable')
        return copy.deepcopy(data[path])
    try:
        result=gate.check_governance(fetch,'fixture-owner/fixture-repo',sha,event,ref)
        assert expected is None, ('unsafe metadata accepted',expected)
        assert result['status']=='PASS' and result['source_sha']==sha
        assert 'organization-secrets' not in ' '.join(requests) or data[base]['owner']['type']=='Organization'
    except gate.GateError as error:
        assert expected is not None and expected in str(error), (str(error),expected)
    passed += 1
check(fixture)
check(fixture,'protected_main_dispatch_required',event='push',ref='refs/tags/v1.2.3')
check(fixture,'protected_main_dispatch_required',ref='refs/heads/unreviewed')
def mutate(path, change, reason):
    data=copy.deepcopy(fixture);change(data[path]);check(data,reason)
protection=base+'/branches/main/protection'
mutate(protection,lambda x:x['required_pull_request_reviews'].update(required_approving_review_count=0),'main_independent_review_missing')
for field in ['dismiss_stale_reviews','require_code_owner_reviews','require_last_push_approval']:
    mutate(protection,lambda x:x['required_pull_request_reviews'].update({field:False}),'main_review_policy_incomplete')
mutate(protection,lambda x:x['required_pull_request_reviews'].update(bypass_pull_request_allowances={'users':[{'id':42}]}),'main_review_bypass_present')
mutate(protection,lambda x:x.update(enforce_admins={'enabled':False}),'main_admin_bypass_enabled')
mutate(protection,lambda x:x['required_status_checks'].update(contexts=[]),'main_required_checks_missing')
for env,secret in gate.ENVIRONMENTS.items():
    prefix=base+'/environments/'+env
    mutate(prefix,lambda x:x.update(protection_rules=[]),'environment_independent_review_missing')
    mutate(prefix,lambda x:x.pop('can_admins_bypass'),'environment_identity_or_admin_policy_unverified')
    mutate(prefix,lambda x:x['protection_rules'][0].update(prevent_self_review=False),'environment_independent_review_missing')
    mutate(prefix,lambda x:x.update(deployment_branch_policy={'protected_branches':True,'custom_branch_policies':False}),'environment_exact_main_policy_missing')
    mutate(prefix+'/deployment-branch-policies',lambda x:x['branch_policies'][0].update(name='v*',type='tag'),'environment_allows_unreviewed_ref')
    mutate(prefix+'/secrets',lambda x:x.update(total_count=0,secrets=[]),'environment_secret_isolation_unverified')
    mutate(prefix+'/secrets',lambda x:x.update(total_count=2,secrets=[{'name':name} for name in sorted(gate.SENSITIVE)]),'environment_secret_isolation_unverified')
    mutate(base+'/actions/secrets',lambda x:x.update(total_count=1,secrets=[{'name':secret}]),'repository_secret_copy_present')
    data=copy.deepcopy(fixture); data[base]['owner']['type']='Organization'
    data[base+'/actions/organization-secrets']={'total_count':1,'secrets':[{'name':secret}]}
    check(data,'accessible_organization_secret_copy_present')
mutate(base,lambda x:x['owner'].update(type='Unknown'),'repository_owner_type_unknown')
mutate(base+'/actions/secrets',lambda x:x.update(total_count=101),'ci_api_incomplete_listing')
data=copy.deepcopy(fixture);del data[protection];check(data,'fixture_metadata_unavailable')
# API collection consumes the same snapshot age; completion must not reset it.
clock={'now':100}; real_time=gate.time.time
try:
    gate.time.time=lambda:clock['now']
    def delayed_fetch(path, params=None):
        clock['now']=250
        return copy.deepcopy(fixture[path])
    report=gate.check_governance(delayed_fetch,'fixture-owner/fixture-repo',sha,'workflow_dispatch','refs/heads/main')
    assert report['checked_at']==100
    passed+=1
finally:
    gate.time.time=real_time
# The real approved-job freshness step must reject expiry, future time, wrong
# source and missing output before the following step receives a release secret.
workflow=(root/'.github/workflows/release.yml').read_text()
for job,upstream,environment,secret in [('sign-release-manifests','signing-governance','release','AEGIS_MANIFEST_SIGNING_KEY'),('publish','publishing-governance','publish','AEGIS_RELEASE_REPO_TOKEN')]:
    block=workflow.split('\n  '+job+':\n',1)[1]
    import re
    block=re.split(r'\n  [a-z][a-z-]*:\n',block,maxsplit=1)[0]
    assert f'environment: {environment}' in block and f'needs.{upstream}.result == \'success\'' in block
    assert "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'" in block
    # The hosted secret-bearing jobs are intentionally unreachable during the
    # B-05 custody hold. Preserve all dormant isolation/freshness checks so a
    # future approved path has to replace this explicit hold in review.
    condition=re.search(r'^    if: (.+)$',block,re.M)
    assert condition and condition.group(1).endswith(' && false }}'), 'hosted credential job is reachable'
    assert block.index('Reject stale governance snapshot after approval') < block.index('secrets.'+secret)
    body=block.split("<<'PYCODE'\n",1)[1].split('\n          PYCODE',1)[0]
    script='\n'.join(line[10:] for line in body.splitlines())
    for age,actual_sha,ok in [(0,sha,True),(301,sha,False),(-10,sha,False),(0,'b'*40,False),(None,sha,False)]:
        env={'PATH':os.environ['PATH'],'GITHUB_SHA':sha,'AEGIS_GOVERNANCE_SOURCE_SHA':actual_sha,'AEGIS_GOVERNANCE_CHECKED_AT':'' if age is None else str(int(time.time())-age)}
        result=subprocess.run([sys.executable,'-I','-c',script],env=env,capture_output=True,timeout=5)
        assert (result.returncode==0)==ok
        passed+=1
    late_step=block.split('      - name: Require fresh governance immediately before credential step\n',1)[1]
    late_body=late_step.split("<<'PYCODE'\n",1)[1].split('\n          PYCODE',1)[0]
    late_script='\n'.join(line[10:] for line in late_body.splitlines())
    # Same original timestamp: entry is age 299, but a simulated download/
    # validation delay makes the final admission age 301. No sleeping or key.
    env={'PATH':os.environ['PATH'],'GITHUB_SHA':sha,'AEGIS_GOVERNANCE_SOURCE_SHA':sha,'AEGIS_GOVERNANCE_CHECKED_AT':'701'}
    for body,now,ok in [(script,1000,True),(late_script,1002,False)]:
        harness='import time; time.time=lambda:'+str(now)+'; exec('+repr(body)+')'
        result=subprocess.run([sys.executable,'-I','-c',harness],env=env,capture_output=True,timeout=5)
        assert (result.returncode==0)==ok
        passed+=1
    secret_step='Sign release manifest (ed25519 anchor)' if job=='sign-release-manifests' else 'Publish GitHub release assets'
    secret_block=block.split('      - name: '+secret_step+'\n',1)[1]
    lines=secret_block.split('        run: |\n',1)[1].splitlines()
    body=[]
    for line in lines:
        if line and not line.startswith('          '):break
        body.append(line[10:] if line else '')
    secret_script='\n'.join(body)+'\n'
    assert secret_script.count('require_fresh_governance\n') >= 2, 'recheck both step admission and immediate credential operation'
    # Scheduling can delay the actual secret-bearing step after its preceding
    # check. Run the real shell step with stale metadata and NO secret or release
    # inputs: it must refuse on freshness before key/PAT/config use, with no files.
    env['AEGIS_GOVERNANCE_CHECKED_AT']=str(int(time.time())-301)
    with tempfile.TemporaryDirectory(prefix='aegis-governance-late-step-') as temp:
        result=subprocess.run(['bash','-c',secret_script],cwd=temp,env=env,capture_output=True,timeout=5)
        assert result.returncode!=0 and b'before credential use' in result.stderr
        assert not list(Path(temp).iterdir())
    passed+=1
assert 'tools/opsec/**' not in (root/'.github/workflows/release-opsec-gate.yml').read_text()
assert workflow.index('Scan unsigned public archives before signing') < workflow.index('  sign-release-manifests:')
assert workflow.index('Scan exact public delivery including compressed archive contents') < workflow.index('Handoff verified public client files')
codeowner_rules=[line.strip() for line in (root/'.github/CODEOWNERS').read_text().splitlines()
                 if line.strip() and not line.lstrip().startswith('#')]
assert codeowner_rules == ['* @whobefaster'], 'independent wildcard CODEOWNER required for all paths'
print(f'PASS: {passed} offline governance/ref/isolation/freshness fixtures; no GitHub or secret values accessed')
PY
