"""The Claude Code hooks, fed hook JSON the way Claude Code sends it.

Run from the repo root: python -m unittest discover tests
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(ROOT, 'hooks', 'claude_code.py')
PW = 'Fake-Passw0rd-xyz'


def run(args, payload, home):
    p = subprocess.run([sys.executable, '-I', HOOK] + args,
                       input=payload if isinstance(payload, str) else json.dumps(payload),
                       capture_output=True, text=True, env=dict(os.environ, CREDVEIL_HOME=home), timeout=30)
    return p.returncode, p.stdout, p.stderr


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = os.path.realpath(self.tmp.name)
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

    def pre(self, tool, tool_input, scope='full', home=None):
        return run(['pre', scope], {'tool_name': tool, 'tool_input': tool_input}, home or self.home)[0]

    def bash(self, cmd, tool='Bash', scope='full'):
        return self.pre(tool, {'command': cmd}, scope)


class Guard(Base):
    def test_direct_device_access_blocked(self):
        for cmd in ['plink -ssh -batch ro@192.0.2.14 "get system status"', 'ssh ro@192.0.2.14',
                    'curl -k https://192.0.2.14/api/v2/monitor/system/status',
                    'C:/PuTTY/plink.exe 192.0.2.14', 'ssh admin@fw1.example.net',
                    'sshpass -p x ssh ro@192.0.2.14']:
            self.assertEqual(self.bash(cmd), 2, cmd)
        self.assertEqual(self.bash('Invoke-RestMethod https://192.0.2.14/api', 'PowerShell'), 2)

    def test_creds_paths_blocked(self):
        for cmd in [f'cat {self.home}/creds/fw1.pw', 'type fw1.pw', f'cat {self.extra}',
                    'Get-Content legacy-creds.txt']:
            self.assertEqual(self.bash(cmd, scope='home'), 2, cmd)

    def test_ordinary_commands_allowed(self):
        for cmd in ['ls -la', 'ping 192.0.2.14', 'git status', 'ssh other-host.example.org',
                    'python credveil.py run fw1 -c "get system status"', 'curl https://example.com',
                    'echo 192.0.2.140 via ssh']:
            self.assertEqual(self.bash(cmd), 0, cmd)

    def test_transport_only_in_command_position(self):
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

    def test_home_scope_leaves_device_access_to_the_skill(self):
        self.assertEqual(self.bash('ssh ro@192.0.2.14', scope='home'), 0)

    def test_inventory_cannot_be_swapped_or_edited(self):
        for cmd in ['CREDVEIL_HOME=/tmp/x python3 credveil.py run fw1 -c x',
                    'export CREDVEIL_HOME=/tmp/x', '$env:CREDVEIL_HOME = "C:/x"',
                    f'sed -i s/192.0.2.14/203.0.113.66/ {self.home}/inventory.toml',
                    f'echo x >> {self.home}/known_hosts']:
            self.assertEqual(self.bash(cmd, scope='home'), 2, cmd)
        for tool, key in (('Edit', 'file_path'), ('Write', 'file_path'), ('MultiEdit', 'file_path')):
            self.assertEqual(self.pre(tool, {key: os.path.join(self.home, 'inventory.toml')}, 'home'), 2, tool)
        self.assertEqual(self.pre('Write', {'file_path': os.path.join(ROOT, 'x.txt')}, 'home'), 0)

    def test_home_scope_ignores_prose(self):
        for cmd in [f'git commit -m "moved inventory to {self.home}; CREDVEIL_HOME=/x documented"',
                    f'cat > notes.md <<EOF\nCREDVEIL_HOME={self.home}\necho x > {self.home}/inventory.toml\nEOF',
                    'grep -n CREDVEIL_HOME= README.md', f'ls {self.home}', f'cat {self.home}/inventory.toml',
                    'echo "set CREDVEIL_HOME in your profile"']:
            self.assertEqual(self.bash(cmd, scope='home'), 0, cmd)

    def test_home_writes_through_an_interpreter_blocked(self):
        cmd = f'python3 - <<EOF\nopen("{self.home}/inventory.toml", "a").write("x")\nEOF'
        self.assertEqual(self.bash(cmd, scope='home'), 2)
        self.assertEqual(self.bash(f'cp evil.toml {self.home}/inventory.toml', scope='home'), 2)

    def test_setup_is_free_before_an_inventory_exists(self):
        empty = os.path.realpath(tempfile.mkdtemp())
        self.assertEqual(self.pre('Write', {'file_path': os.path.join(empty, 'inventory.toml')}, 'home', empty), 0)
        self.assertEqual(self.pre('Bash', {'command': 'ssh 192.0.2.14'}, 'full', empty), 0)

    def test_read_and_grep(self):
        pw = os.path.join(self.home, 'creds', 'fw1.pw')
        for path in (pw, os.path.join(self.home, 'creds', '..', 'creds', 'fw1.pw'),
                     os.path.join(self.home, 'x', '..', 'creds', 'fw1.pw')):
            self.assertEqual(self.pre('Read', {'file_path': path}, 'home'), 2, path)
        self.assertEqual(self.pre('Grep', {'pattern': 'x', 'path': self.home}, 'home'), 2)
        self.assertEqual(self.pre('Read', {'file_path': os.path.join(self.home, 'inventory.toml')}, 'home'), 0)

    @unittest.skipIf(os.name == 'nt', 'symlinks need privileges on Windows')
    def test_symlink_into_creds_blocked(self):
        link = os.path.join(tempfile.mkdtemp(), 'c')
        os.symlink(os.path.join(self.home, 'creds'), link)
        self.assertEqual(self.pre('Read', {'file_path': os.path.join(link, 'fw1.pw')}, 'home'), 2)

    def test_broken_input_fails_open(self):
        self.assertEqual(run(['pre', 'full'], 'not json', self.home)[0], 0)
        empty = tempfile.mkdtemp()
        self.assertEqual(self.pre('Bash', {'command': 'ssh 192.0.2.14'}, 'full', empty), 0)


class OutNet(Base):
    def post(self, tool, resp, tool_input=None):
        rc, out, err = run(['post'], {'hook_event_name': 'PostToolUse', 'tool_name': tool,
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

    def test_recognised_export_gets_the_full_pack(self):
        export = ('Building configuration...\n\nCurrent configuration : 1234 bytes\n!\nhostname R1\n'
                  'username ops password 7 0822455D0A16\ncrypto isakmp key PlantedPsk1 address 0.0.0.0\n'
                  'snmp-server community s3cretRO RO\ninterface Gi0/0\n ip address 192.0.2.1 255.255.255.0\n')
        new = self.post('Read', {'type': 'text', 'file': {'filePath': '/x/r1.cfg', 'content': export}},
                        {'file_path': '/x/r1.cfg'})['file']['content']
        for s in ('0822455D0A16', 'PlantedPsk1', 's3cretRO'):
            self.assertNotIn(s, new)
        self.assertIn('ip address 192.0.2.1 255.255.255.0', new)

    def test_clean_output_untouched(self):
        self.assertIsNone(self.post('Bash', {'stdout': 'password = get_pw()\nok', 'stderr': ''}))

    def test_own_sources_skipped(self):
        fp = os.path.join(ROOT, 'tests', 'test_claude_code.py')
        resp = {'type': 'text', 'file': {'filePath': fp, 'content': 'ENC Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdo'}}
        self.assertIsNone(self.post('Read', resp, {'file_path': fp}))


if __name__ == '__main__':
    unittest.main()
