#!/usr/bin/env bash
# Evaluate actual workflow job conditions offline; never dispatch or build.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
python3 - "$ROOT" <<'PY'
import ast, itertools, pathlib, re, sys
root = pathlib.Path(sys.argv[1])
source = (root/'.github/workflows/release.yml').read_text()
inputs = source.split('    inputs:\n',1)[1].split('\n#',1)[0]
setting = re.search(r'^      build_only:\n(?:(?:        .*|)\n)+', inputs, re.M)[0]
assert 'required: false' in setting and 'default: false' in setting and 'type: boolean' in setting
assert '      tag_name:\n' in inputs
jobs = {match[1]: match[2] for match in re.finditer(r'^  ([a-z0-9_-]+):\n(.*?)(?=^  [a-z0-9_-]+:\n|\Z)', source.split('\njobs:\n',1)[1], re.M|re.S)}
assert set(jobs) == {'build-macos-client','build-linux-arm64','build-linux-x86_64','assemble-delivery','sign-release-manifests','prepare-public-client','publish','signing-governance','publishing-governance'}
required = {
    'assemble-delivery': ('build-linux-x86_64','build-linux-arm64'),
    'signing-governance': ('assemble-delivery',),
    'sign-release-manifests': ('assemble-delivery','signing-governance'),
    'prepare-public-client': ('assemble-delivery','sign-release-manifests'),
    'publishing-governance': ('prepare-public-client',),
    'publish': ('prepare-public-client','publishing-governance'),
}

def evaluate(condition, event, build_only, publish_release, needs, cancelled, ref):
    # Interpret just the boolean/comparison grammar actually used by these
    # jobs. Unknown syntax or variables fail the contract, rather than being
    # approximated by a separately handwritten copy of the condition.
    names = {'github.event_name': event, 'github.ref': ref, 'inputs.build_only': build_only,
             'inputs.publish_release': publish_release,
             **{'needs.'+key+'.result': value for key,value in needs.items()}}
    condition = re.sub(r'(?:github\.(?:event_name|ref)|inputs\.(?:build_only|publish_release)|needs\.[a-z0-9_-]+\.result)', lambda m: repr(names[m[0]]), condition)
    condition = condition.replace('always()', 'True').replace('cancelled()', repr(cancelled))
    condition = re.sub(r'\bfalse\b', 'False', condition)
    condition = condition.replace('&&', ' and ').replace('||', ' or ')
    condition = re.sub(r'!(?!=)', ' not ', condition).strip()
    node = ast.parse(condition, mode='eval').body
    def walk(value):
        if isinstance(value, ast.Constant): return value.value
        if isinstance(value, ast.BoolOp):
            assert isinstance(value.op, (ast.And, ast.Or))
            values = [bool(walk(item)) for item in value.values]
            return all(values) if isinstance(value.op, ast.And) else any(values)
        if isinstance(value, ast.UnaryOp):
            assert isinstance(value.op, ast.Not)
            return not walk(value.operand)
        if isinstance(value, ast.Compare):
            assert len(value.ops) == len(value.comparators) == 1 and isinstance(value.ops[0], (ast.Eq, ast.NotEq))
            equal = walk(value.left) == walk(value.comparators[0])
            return equal if isinstance(value.ops[0], ast.Eq) else not equal
        raise AssertionError(('unsupported workflow expression', ast.dump(value)))
    return bool(walk(node))

cases = 0
for job, dependencies in required.items():
    condition = re.findall(r'^    if: \$\{\{ (.+) \}\}$', jobs[job], re.M)
    assert len(condition) == 1
    condition = condition[0]
    if job in ('sign-release-manifests', 'publish'):
        assert condition.endswith(' && false'), (job, 'B-05 hosted credential hold missing')
    if job == 'publish':
        assert 'inputs.publish_release' in condition
    assert "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main' && !inputs.build_only" in condition
    for event, build_only, publish_release in (
        ('push',None,None), ('push',True,False),
        ('workflow_dispatch',None,None), ('workflow_dispatch',False,False),
        ('workflow_dispatch',False,True), ('workflow_dispatch',True,True),
    ):
        for statuses in itertools.product(('success','failure','skipped','cancelled'), repeat=len(dependencies)):
            needs = dict(zip(dependencies,statuses))
            for cancelled, ref in itertools.product((False,True), ('refs/heads/main','refs/heads/unreviewed','refs/tags/v1.2.3')):
                actual = evaluate(condition,event,build_only,publish_release,needs,cancelled,ref)
                # Preserve existing normal-release cancellation behavior:
                # assembler uses always(); signing and publication do not.
                previous = all(status == 'success' for status in statuses) and (job == 'assemble-delivery' or not cancelled)
                expected = previous and event == 'workflow_dispatch' and ref == 'refs/heads/main' and build_only is not True
                if job == 'publish' and event == 'workflow_dispatch':
                    expected = expected and publish_release is True
                if job in ('sign-release-manifests', 'publish'):
                    expected = False
                assert actual == expected, (job,event,build_only,publish_release,needs,cancelled,actual)
                cases += 1
    print('PASS build-only gate:',job)

wrapper = (root/'scripts/build-container-release-delivery.sh').read_text()
assert re.search(r'^OUTPUT=/aegis-delivery$', wrapper, re.M), 'container wrapper output changed'
assert re.search(r'^bash "\$\{ROOT\}/scripts/build-release-delivery.sh" "\$\{OUTPUT\}" "\$@"$', wrapper, re.M), 'container wrapper must delegate the original builder with the isolated output and original arguments'
for name, output in (('build-linux-x86_64','linux-x86_64'), ('build-linux-arm64','arm64')):
    builder = jobs[name]
    assert not re.search(r'^    (?:if|needs|environment):', builder, re.M)
    assert 'inputs.build_only' not in builder and 'inputs.tag_name' not in builder
    assert 'secrets.' not in builder and 'gh release' not in builder
    assert 'almalinux:9@sha256:' in builder
    # Follow the actual strict output wrapper; it owns the mount and restores
    # runner ownership. A direct legacy invocation cannot replace this boundary.
    active = '\n'.join(line for line in builder.splitlines() if not line.lstrip().startswith('#'))
    assert len(re.findall(r'^\s+bash \./scripts/build-container-release-delivery\.sh \\$', active, re.M)) == 1, (name, 'missing container wrapper')
    assert 'bash ./scripts/build-release-delivery.sh' not in active, (name, 'direct builder bypasses isolated output')
    assert f'-v "$PWD/dist/{output}":/aegis-delivery \\' in active, (name, 'wrong output mount')
    assert '-v "$PWD":/src -w /src \\' in active, (name, 'missing source mount')
    assert '-e AEGIS_DELIVERY_UID="$(id -u)" \\' in active, (name, 'missing runner UID')
    assert '-e AEGIS_DELIVERY_GID="$(id -g)" \\' in active, (name, 'missing runner GID')
    assert '--channel "${AEGIS_RELEASE_CHANNEL}" \\' in active and '--prerelease "${AEGIS_RELEASE_PRERELEASE}"' in active, (name, 'missing original release arguments')
    assert 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' in builder and 'retention-days: 7' in builder
assert 'Require exact-source main CI' in jobs['assemble-delivery']
assert 'environment: release' in jobs['sign-release-manifests']
assert "github.event_name != 'workflow_dispatch' || inputs.include_macos" in jobs['build-macos-client']
assert len(re.findall(r'inputs\.build_only', source)) == 6
assert 'environment: publish' in jobs['publish']
print(f'PASS: {cases} actual job-condition cases; unsigned tag/build-only behavior and protected main-only release boundaries')
PY
