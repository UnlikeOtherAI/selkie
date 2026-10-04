#!/usr/bin/env python3
"""Exercise the workflow's real rsync filters without network or production data."""
from pathlib import Path
import re
import subprocess
import tempfile

project = Path(__file__).resolve().parent.parent
workflow = (project / '.github/workflows/deploy.yml').read_text()
patterns = re.findall(r"--exclude '([^']+)'", workflow)
assert patterns, 'No source synchronization exclusions found'
build = project / '.build'
build.mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='deploy-source-test.', dir=build) as work:
    source = Path(work) / 'source'
    destination = Path(work) / 'destination'
    source.mkdir()
    destination.mkdir()
    included = [
        'cmd/control-server/main.go', 'cmd/control-server-new/main.go',
        'cmd/home-peer/main.go', 'internal/direct/handler.go',
        'nested/App/service.go', 'nested/e2e/helper.go',
        'Dockerfile', 'go.mod', '.github/workflows/deploy.yml',
    ]
    excluded = [
        'control-server', 'control-server-new', '.env', '.git',
        '.build/artifact', '.worktrees/private/file',
        'admin-ui/node_modules/dependency', 'App/ios/file', 'e2e/test.ts',
        'source.tar', '.playwright-cli/session', '.playwright-mcp/session',
    ]
    for relative in included + excluded:
        file = source / relative
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text('new source\n')
    stale = destination / 'cmd/control-server/main.go'
    stale.parent.mkdir(parents=True)
    stale.write_text('stale deployed main without direct routes\n')
    private_env = destination / '.env'
    private_env.write_text('deployment-owned fixture\n')
    command = ['rsync', '-a', '--delete']
    for pattern in patterns:
        command.extend(['--exclude', pattern])
    subprocess.run(command + [str(source) + '/', str(destination) + '/'], check=True)
    for relative in included:
        assert (destination / relative).read_text() == 'new source\n', relative
    for relative in excluded:
        if relative != '.env':
            assert not (destination / relative).exists(), relative
    assert private_env.read_text() == 'deployment-owned fixture\n'
print('Source sync passed: current server routes copied; root binaries, secrets, and build artifacts excluded.')
