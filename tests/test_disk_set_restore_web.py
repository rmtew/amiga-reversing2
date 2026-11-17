"""Exercise Restore's browser request scope without a browser installation."""

import shutil
import subprocess
from pathlib import Path

import pytest


def test_restore_requests_bind_selected_member_and_discard_old_verification(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Restore client execution requires Node.js")
    source = Path(__file__).resolve().parents[1] / "amiga_reversing/web/restoration.js"
    script = tmp_path / "restore-client.js"
    script.write_text("""
const assert = require('node:assert/strict');
const state = {project: 'synthetic owner'};
const calls = [];
let resolveRequest;
let busy = null;
let current = 'r1';
const media = [{value: '/tmp/synthetic.adf', dataset: {restoreMedia: 'disk'}}];
const scope = {querySelectorAll: () => media};
const proofDisplay = {textContent: 'old receipt'};
const panel = {
  isConnected: true,
  querySelector: id => id === '#restoration-scope' ? scope : proofDisplay,
  getAttribute: () => busy,
  setAttribute: (_, value) => { busy = value; },
  removeAttribute: () => { busy = null; },
};
const document = {
  addEventListener() {},
  getElementById(id) { return id === 'restoration-panel' ? panel : null; },
};
function fetchJson(url, options) {
  calls.push({url, body: JSON.parse(options.body)});
  return Promise.resolve(resolveRequest ? resolveRequest() : {revision: current});
}
""" + source.read_text() + """
(async () => {
  restorationView.project = state.project;
  restorationView.member = {id: 'shared', analysis_owner: 'main'};
  restorationView.revision = current;
  restorationView.verificationId = 'old receipt';
  await restorationRun('inspect', {source_offset: 0});
  assert.equal(calls[0].url, '/api/projects/synthetic%20owner/restoration');
  assert.deepEqual(calls[0].body, {
    operation: 'inspect', source_offset: 0, member_id: 'shared', media_paths: {disk: '/tmp/synthetic.adf'},
  });
  current = 'r2';
  await restorationRun('interpret', {expected_revision: 'r1'});
  assert.equal(restorationView.verificationId, null);
  assert.equal(proofDisplay.textContent, '');
  restorationView.member = {id: 'overlay', analysis_owner: 'overlay'};
  await restorationRun('history', {expected_revision: 'r2'});
  assert.equal(calls[2].body.member_id, 'overlay');
  await restorationRun('state');
  assert.deepEqual(calls[3].body, {operation: 'state'});
  media[0].value = '';
  await assert.rejects(restorationRun('review'), /Incomplete disk set bindings/);
  assert.equal(calls.length, 4);
  media[0].value = '/tmp/synthetic.adf';
  resolveRequest = () => { panel.isConnected = false; return {revision: 'late'}; };
  await assert.rejects(restorationRun('history'), /Restore view closed/);
  assert.equal(restorationView.revision, 'r2');
})().catch(error => { console.error(error); process.exitCode = 1; });
""")
    result = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
