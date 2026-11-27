"""Tests for credveil_guard.py and credveil_outnet.py, fed hook JSON the way Claude Code sends it.

Run: python -m unittest -v (in this folder).
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PW = 'Fake-Passw0rd-xyz'


def run(script, payload, home):
    env = dict(os.environ, CREDVEIL_HOME=home)
    p = subprocess.run([sys.executable, '-I', os.path.join(HERE, script)], input=json.dumps(payload),
                       capture_output=True, text=True, env=env, timeout=30)
    return p.returncode, p.stdout, p.stderr


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = self.tmp.name
        os.makedirs(os.path.join(self.home, 'creds'))
        with open(os.path.join(self.home, 'creds', 'fw1.pw'), 'w') as fh:
            fh.write(PW)
        self.extra = os.path.join(self.home, 'old', 'legacy-creds.txt').replace('\\', '/')
        with open(os.path.join(self.home, 'inventory.toml'), 'w') as fh:
            fh.write('[guard]\nhosts = ["fw1.example.net"]\n'
                     f'protect = ["{self.extra}"]\n\n'
                     '[device.fw1]\nhost = "192.0.2.14"\nvendor = "fortios"\n'
                     'password_file = "creds/fw1.pw"\n')

    def tearDown(self):
        self.tmp.cleanup()


class Guard(Base):
    def bash(self, cmd, tool='Bash'):
        return run('credveil_guard.py', {'tool_name': tool, 'tool_input': {'command': cmd}}, self.home)[0]

    def test_direct_device_access_blocked(self):
        for cmd in ['plink -ssh -batch ro@192.0.2.14 "get system status"',
                    'ssh ro@192.0.2.14', 'curl -k https://192.0.2.14/api/v2/monitor/system/status',
                    'C:/PuTTY/plink.exe 192.0.2.14', 'ssh admin@fw1.example.net']:
            self.assertEqual(self.bash(cmd), 2, cmd)
        self.assertEqual(self.bash('Invoke-RestMethod https://192.0.2.14/api', 'PowerShell'), 2)

    def test_creds_paths_blocked(self):
        for cmd in [f'cat {self.home}/creds/fw1.pw', 'cat ~/.config/credveil/creds/fw1.pw',
                    'type fw1.pw', f'cat {self.extra}', 'Get-Content legacy-creds.txt']:
            # ~/.config/credveil/... only matches when CREDVEIL_HOME is the default; the basename always does
            self.assertEqual(self.bash(cmd), 2, cmd)

    def test_ordinary_commands_allowed(self):
        for cmd in ['ls -la', 'ping 192.0.2.14', 'git status', 'ssh other-host.example.org',
                    'python credveil.py run fw1 -c "get system status"', 'curl https://example.com',
                    'echo 192.0.2.140 via ssh']:
            self.assertEqual(self.bash(cmd), 0, cmd)

    def test_transport_only_in_command_position(self):
        # FP-2: prose, commit messages and heredoc bodies naming the device never block
        for cmd in ['git commit -m "fw1.example.net checked via SSH and curl"',
                    "git add log.md && git commit -q -m 'credveil live on fw1.example.net: SSH, REST'",
                    'python edit.py <<\'EOF\'\nssh to fw1.example.net verified\nEOF\ngit push',
                    'echo "plink 192.0.2.14" >> notes.md',
                    'cat > log.txt <<EOF\ncurl https://192.0.2.14 worked\nEOF']:
            self.assertEqual(self.bash(cmd), 0, cmd)

    def test_transport_through_wrappers_still_blocked(self):
        for cmd in ['FOO=1 timeout 5 ssh ro@192.0.2.14', 'cd /tmp && plink -batch 192.0.2.14 x',
                    'bash -c "ssh 192.0.2.14 get system status"', 'echo x | ssh 192.0.2.14',
                    'out=$(curl -sk https://192.0.2.14/api)', '& "C:/Program Files/PuTTY/plink.exe" 192.0.2.14',
                    'python -c "import requests; requests.get(\'https://192.0.2.14\')"',
                    'python - <<EOF\nimport socket\nsocket.create_connection(("192.0.2.14", 22))\nEOF']:
            self.assertEqual(self.bash(cmd), 2, cmd)
        self.assertEqual(self.bash('$r = Invoke-RestMethod https://192.0.2.14/api', 'PowerShell'), 2)

    def test_read_and_grep(self):
        pw = os.path.join(self.home, 'creds', 'fw1.pw')
        self.assertEqual(run('credveil_guard.py', {'tool_name': 'Read', 'tool_input': {'file_path': pw}}, self.home)[0], 2)
        self.assertEqual(run('credveil_guard.py', {'tool_name': 'Grep', 'tool_input': {'pattern': 'x', 'path': self.home}},
                             self.home)[0], 2)
        ok = os.path.join(self.home, 'inventory.toml')
        self.assertEqual(run('credveil_guard.py', {'tool_name': 'Read', 'tool_input': {'file_path': ok}}, self.home)[0], 0)

    def test_no_inventory_fails_open(self):
        empty = tempfile.mkdtemp()
        self.assertEqual(run('credveil_guard.py', {'tool_name': 'Bash', 'tool_input': {'command': 'ssh 192.0.2.14'}},
                             empty)[0], 0)

    def test_garbage_input_fails_open(self):
        p = subprocess.run([sys.executable, '-I', os.path.join(HERE, 'credveil_guard.py')], input='not json',
                           capture_output=True, text=True, env=dict(os.environ, CREDVEIL_HOME=self.home))
        self.assertEqual(p.returncode, 0)


class OutNet(Base):
    def post(self, tool, resp, tool_input=None):
        rc, out, err = run('credveil_outnet.py', {'hook_event_name': 'PostToolUse', 'tool_name': tool,
                                              'tool_input': tool_input or {}, 'tool_response': resp}, self.home)
        self.assertEqual(rc, 0, err)
        return json.loads(out)['hookSpecificOutput']['updatedToolOutput'] if out.strip() else None

    def test_bash_output_masked_shape_kept(self):
        resp = {'stdout': 'set psksecret ENC Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdo\nlogin ' + PW,
                'stderr': '', 'interrupted': False, 'isImage': False, 'noOutputExpected': False}
        new = self.post('Bash', resp)
        self.assertEqual(set(new), set(resp))
        self.assertNotIn('Zm9vYmFy', new['stdout'])
        self.assertNotIn(PW, new['stdout'])

    def test_read_output_masked(self):
        resp = {'type': 'text', 'file': {'filePath': '/x/export.conf', 'numLines': 3,
                                         'content': 'a\n-----BEGIN RSA PRIVATE KEY-----\nPlantedK\n-----END RSA PRIVATE KEY-----\n'}}
        new = self.post('Read', resp, {'file_path': '/x/export.conf'})
        self.assertNotIn('PlantedK', new['file']['content'])
        self.assertEqual(new['file']['numLines'], 3)

    def test_clean_output_untouched(self):
        self.assertIsNone(self.post('Bash', {'stdout': 'password = get_pw()\nok', 'stderr': ''}))

    def test_credveil_skill_files_skipped(self):
        fp = os.path.join(HERE, 'test_hooks.py')
        resp = {'type': 'text', 'file': {'filePath': fp, 'content': 'ENC Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdo'}}
        self.assertIsNone(self.post('Read', resp, {'file_path': fp}))


if __name__ == '__main__':
    unittest.main()
