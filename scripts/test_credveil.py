"""End-to-end tests for credveil.py with a fake device (transport = "exec").

Run: python -m unittest -v (in this folder). No network, no real credentials.
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import credveil  # noqa: E402

PW = 'Fake-Passw0rd-xyz'
TOKEN = 'faketoken0123456789abcdefghijklmn'

FAKE_DEVICE = textwrap.dedent('''\
    import sys
    arg = sys.argv[-1]
    mode = sys.argv[1]
    if mode == 'ssh':
        cmds = open(arg, encoding='utf-8').read()
        print('FGT (Branch) # ' + cmds.replace('\\n', ' | '))
        print('    set psksecret ENC Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdo')
        print('  dec: spi=8a1b2c3d esp=aes key=16 00112233445566778899aabbccddeeff')
    elif mode == 'leak':
        print('banner ' + open(sys.argv[2], encoding='utf-8').read().strip())
    elif mode == 'stderr':
        print('ok')
        print('error near psksecret ENC Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdo', file=sys.stderr)
        sys.exit(3)
    elif mode == 'api':
        print('{"results": [{"name": "S2S", "psksecret": "ENC Zm9vYmFyYmF6cXV4MTIz", "url": "%s"}], '
              '"status": "success"}' % arg)
''')


class CredveilE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        h = self.tmp.name
        os.makedirs(os.path.join(h, 'creds'))
        with open(os.path.join(h, 'creds', 'fw.pw'), 'w') as fh:
            fh.write(PW + '\n')
        with open(os.path.join(h, 'creds', 'fw.token'), 'w') as fh:
            fh.write(TOKEN + '\n')
        fake = os.path.join(h, 'fake_device.py')
        with open(fake, 'w') as fh:
            fh.write(FAKE_DEVICE)
        py = sys.executable.replace('\\', '/')
        fake = fake.replace('\\', '/')
        pwf = os.path.join(h, 'creds', 'fw.pw').replace('\\', '/')

        def dev(name, mode, extra=''):
            return (f'[device.{name}]\nhost = "192.0.2.14"\nvendor = "fortios"\nuser = "ro"\n'
                    f'password_file = "creds/fw.pw"\ntoken_file = "creds/fw.token"\n'
                    f'tls_pin = "sha256//AAAA"\ntransport = "exec"\n'
                    f'exec = ["{py}", "{fake}", "{mode}"{extra}]\n\n')
        with open(os.path.join(h, 'inventory.toml'), 'w') as fh:
            fh.write(dev('fw', 'ssh') + dev('leaky', 'leak', f', "{pwf}"') + dev('noisy', 'stderr')
                     + dev('api', 'api'))
        os.environ['CREDVEIL_HOME'] = h

    def tearDown(self):
        os.environ.pop('CREDVEIL_HOME', None)
        self.tmp.cleanup()

    def run_credveil(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        old = sys.stdin
        sys.stdin = io.StringIO(stdin or '')
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = credveil.main(list(argv))
        finally:
            sys.stdin = old
        return rc, out.getvalue(), err.getvalue()

    def test_run_masks_and_wraps_vdom(self):
        rc, out, err = self.run_credveil('run', 'fw', '--vdom', 'Branch', '-c', 'show vpn ipsec phase1-interface')
        self.assertEqual(rc, 0, err)
        self.assertIn('config vdom | edit Branch | show vpn ipsec phase1-interface | end', out)
        self.assertNotIn('Zm9vYmFy', out)
        self.assertNotIn('00112233445566778899', out)
        self.assertIn('spi=8a1b2c3d', out)
        self.assertIn('credveil: masked', err)

    def test_commands_from_stdin(self):
        rc, out, _ = self.run_credveil('run', 'fw', stdin='get system status\n\nget router info ospf neighbor\n')
        self.assertEqual(rc, 0)
        self.assertIn('get system status | get router info ospf neighbor', out)

    def test_known_password_withholds_everything(self):
        rc, out, err = self.run_credveil('run', 'leaky', '-c', 'x')
        self.assertEqual(rc, credveil.EXIT_LEAK)
        self.assertEqual(out, '')
        self.assertNotIn(PW, err)
        self.assertIn('withheld', err)

    def test_stderr_masked_and_rc_passed_through(self):
        rc, out, err = self.run_credveil('run', 'noisy', '-c', 'x')
        self.assertEqual(rc, 3)
        self.assertIn('ok', out)
        self.assertNotIn('Zm9vYmFy', err)

    def test_get_json_masked(self):
        rc, out, err = self.run_credveil('get', 'api', '/api/v2/cmdb/vpn.ipsec/phase1-interface',
                                     '--vdom', 'Branch', '-p', 'filter=name==S2S')
        self.assertEqual(rc, 0, err)
        body = json.loads(out)
        self.assertEqual(body['results'][0]['psksecret'], '<masked>')
        self.assertIn('vdom=Branch', body['results'][0]['url'])
        self.assertIn('filter=name%3D%3DS2S', body['results'][0]['url'])
        self.assertNotIn(TOKEN, out + err)

    def test_get_rejects_other_paths_and_queries(self):
        for p in ('/api/v2/monitor/system/status?access_token=x', '/logincheck',
                  '/api/v2/monitor/../cmdb/x'):
            rc, _, _ = self.run_credveil('get', 'api', p)
            self.assertEqual(rc, credveil.EXIT_USAGE, p)
        rc, _, _ = self.run_credveil('get', 'api', '/api/v2/monitor/system/status', '-p', 'access_token=x')
        self.assertEqual(rc, credveil.EXIT_USAGE)

    def test_get_undoes_git_bash_path_rewrite(self):
        # TF-1: MSYS turns /api/v2/... into C:/Program Files/Git/api/v2/...
        rc, out, err = self.run_credveil('get', 'api', 'C:/Program Files/Git/api/v2/monitor/system/status')
        self.assertEqual(rc, 0, err)
        self.assertIn('/api/v2/monitor/system/status', json.loads(out)['results'][0]['url'])
        for p in ('C:/Program Files/Git/api/v2/monitor/../cmdb/x', 'C:/Windows/notapi/v2/x'):
            self.assertEqual(self.run_credveil('get', 'api', p)[0], credveil.EXIT_USAGE, p)

    def test_mask_keeps_input_line_endings(self):
        # TF-2: the output follows the input file, on every OS, so diff raw/masked shows only real changes
        code = ('import sys; sys.path.insert(0, sys.argv[1]); import credveil; '
                'sys.exit(credveil.main(["mask", "--vendor", "fortios"] + sys.argv[2:]))')
        here = os.path.dirname(os.path.abspath(credveil.__file__))
        secret = b'    set password ENC Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5'
        for eol in (b'\n', b'\r\n'):
            raw = os.path.join(self.tmp.name, 'eol.txt')
            with open(raw, 'wb') as fh:
                fh.write(b'line one' + eol + secret + eol)
            with open(raw, 'rb') as fh:
                data = fh.read()
            for args, stdin in (([raw], None), ([], data)):
                p = subprocess.run([sys.executable, '-c', code, here] + args, input=stdin, capture_output=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, b'line one' + eol + b'    set password <masked>' + eol, (eol, args))
        rc, out, _ = self.run_credveil('run', 'fw', '-c', 'x')
        self.assertNotIn('\r', out)

    def test_vdom_only_for_fortios_and_unknown_alias(self):
        rc, _, err = self.run_credveil('run', 'nope', '-c', 'x')
        self.assertEqual(rc, credveil.EXIT_USAGE)
        self.assertIn('unknown device', err)

    def test_list_shows_no_secret_values(self):
        rc, out, _ = self.run_credveil('list')
        self.assertEqual(rc, 0)
        self.assertIn('fw', out)
        self.assertNotIn(PW, out)
        self.assertNotIn(TOKEN, out)

    def test_ssh_argv_never_carries_the_password(self):
        inv = credveil.load_inventory()
        d = credveil.device(inv, 'fw')
        d['hostkey'] = 'SHA256:abc'
        d['ssh_client'] = 'plink'
        orig = credveil.shutil.which
        credveil.shutil.which = lambda n: '/usr/bin/' + n
        try:
            argv, env = credveil.ssh_argv(d, 'cmds.txt', self.tmp.name)
        finally:
            credveil.shutil.which = orig
        self.assertNotIn(PW, ' '.join(argv))
        self.assertIn('-pwfile', argv)
        self.assertIn('-batch', argv)
        self.assertEqual(argv[argv.index('-hostkey') + 1], 'SHA256:abc')

    def test_audit_prints_no_values(self):
        raw = os.path.join(self.tmp.name, 'raw.txt')
        with open(raw, 'w') as fh:
            fh.write('hostname x\n    set password ENC Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5\nplain\n')
        rc, out, _ = self.run_credveil('audit', '--vendor', 'fortios', raw)
        self.assertEqual(rc, 0)
        self.assertNotIn('Zm9vYmFy', out)
        self.assertIn('touched lines: 2', out)


if __name__ == '__main__':
    unittest.main()
