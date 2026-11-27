"""End-to-end tests for the credveil CLI with fake transports. No network, no real credentials.

Run from the repo root: python -m unittest discover tests
"""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from credveil import cli, config, connectors  # noqa: E402
from credveil.connectors import Result, https, ssh  # noqa: E402

PW = 'Fake-Passw0rd-xyz'
TOKEN = 'faketoken0123456789abcdefghijklmn'
PSK_LINE = '    set psksecret ENC Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdo'


def fake_ssh(d, cmds, timeout):
    mode = d['alias']
    if mode == 'leaky':
        return Result(f'banner {PW}\n', '', 0)
    if mode == 'noisy':
        return Result('ok\n', 'error near ' + PSK_LINE.strip() + '\n', 3)
    return Result('FGT (Branch) # ' + ' | '.join(cmds) + '\n' + PSK_LINE + '\n'
                  '  dec: spi=8a1b2c3d esp=aes key=16 00112233445566778899aabbccddeeff\n', '', 0)


def fake_https_get(d, profile, url, timeout):
    body = {'results': [{'name': 'S2S', 'psksecret': 'ENC Zm9vYmFyYmF6cXV4MTIz', 'url': url}],
            'status': 'success'}
    return Result(json.dumps(body), '', 0)


class CliE2E(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        h = self.tmp.name
        os.makedirs(os.path.join(h, 'creds'))
        for name, val in (('fw.pw', PW), ('fw.token', TOKEN)):
            with open(os.path.join(h, 'creds', name), 'w') as fh:
                fh.write(val + '\n')
        dev = ('host = "192.0.2.14"\nvendor = "fortios"\nuser = "ro"\npassword_file = "creds/fw.pw"\n'
               'token_file = "creds/fw.token"\ntls_pin = "sha256//AAAA"\n')
        with open(os.path.join(h, 'inventory.toml'), 'w') as fh:
            fh.write(''.join(f'[device.{n}]\n{dev}\n' for n in ('fw', 'leaky', 'noisy', 'api')))
            fh.write('[device.sw]\nhost = "192.0.2.20"\nvendor = "aos-cx"\n')
        os.environ['CREDVEIL_HOME'] = h
        self.stack = ExitStack()
        self.stack.enter_context(connectors.use('ssh', SimpleNamespace(run=fake_ssh)))
        self.stack.enter_context(connectors.use('https', SimpleNamespace(build_url=https.build_url,
                                                                        get=fake_https_get)))

    def tearDown(self):
        self.stack.close()
        os.environ.pop('CREDVEIL_HOME', None)
        self.tmp.cleanup()

    def run_cli(self, *argv, stdin=None):
        out, err = io.StringIO(), io.StringIO()
        old = sys.stdin
        sys.stdin = io.StringIO(stdin or '')
        try:
            with redirect_stdout(out), redirect_stderr(err):
                rc = cli.main(list(argv))
        finally:
            sys.stdin = old
        return rc, out.getvalue(), err.getvalue()

    def test_run_masks_and_wraps_vdom(self):
        rc, out, err = self.run_cli('run', 'fw', '--vdom', 'Branch', '-c', 'show vpn ipsec phase1-interface')
        self.assertEqual(rc, 0, err)
        self.assertIn('config vdom | edit Branch | show vpn ipsec phase1-interface | end', out)
        self.assertNotIn('Zm9vYmFy', out)
        self.assertNotIn('00112233445566778899', out)
        self.assertIn('spi=8a1b2c3d', out)
        self.assertIn('credveil: masked', err)

    def test_commands_from_stdin(self):
        rc, out, _ = self.run_cli('run', 'fw', stdin='get system status\n\nget router info ospf neighbor\n')
        self.assertEqual(rc, 0)
        self.assertIn('get system status | get router info ospf neighbor', out)

    def test_known_password_withholds_everything(self):
        rc, out, err = self.run_cli('run', 'leaky', '-c', 'x')
        self.assertEqual(rc, cli.EXIT_LEAK)
        self.assertEqual(out, '')
        self.assertNotIn(PW, err)
        self.assertIn('withheld', err)

    def test_masking_failure_withholds_everything(self):
        with connectors.use('ssh', SimpleNamespace(run=lambda d, c, t: Result(object(), '', 0))):
            rc, out, err = self.run_cli('run', 'fw', '-c', 'x')
        self.assertEqual((rc, out), (cli.EXIT_MASKFAIL, ''))

    def test_stderr_masked_and_rc_passed_through(self):
        rc, out, err = self.run_cli('run', 'noisy', '-c', 'x')
        self.assertEqual(rc, 3)
        self.assertIn('ok', out)
        self.assertNotIn('Zm9vYmFy', err)

    def test_context_only_where_the_pack_has_one(self):
        rc, _, err = self.run_cli('run', 'sw', '--vdom', 'x', '-c', 'show run')
        self.assertEqual(rc, cli.EXIT_USAGE)
        self.assertIn('do not apply', err)

    def test_get_json_masked(self):
        rc, out, err = self.run_cli('get', 'api', '/api/v2/cmdb/vpn.ipsec/phase1-interface',
                                    '--vdom', 'Branch', '-p', 'filter=name==S2S')
        self.assertEqual(rc, 0, err)
        body = json.loads(out)
        self.assertEqual(body['results'][0]['psksecret'], '<masked>')
        self.assertIn('vdom=Branch', body['results'][0]['url'])
        self.assertIn('filter=name%3D%3DS2S', body['results'][0]['url'])
        self.assertNotIn(TOKEN, out + err)

    def test_get_rejects_other_paths_and_queries(self):
        for p in ('/api/v2/monitor/system/status?access_token=x', '/logincheck', '/api/v2/monitor/../cmdb/x'):
            self.assertEqual(self.run_cli('get', 'api', p)[0], cli.EXIT_USAGE, p)
        rc, _, _ = self.run_cli('get', 'api', '/api/v2/monitor/system/status', '-p', 'access_token=x')
        self.assertEqual(rc, cli.EXIT_USAGE)
        rc, _, err = self.run_cli('get', 'sw', '/api/v2/monitor/x')
        self.assertEqual(rc, cli.EXIT_USAGE)
        self.assertIn('no REST profile', err)

    def test_get_undoes_git_bash_path_rewrite(self):
        rc, out, err = self.run_cli('get', 'api', 'C:/Program Files/Git/api/v2/monitor/system/status')
        self.assertEqual(rc, 0, err)
        self.assertIn('/api/v2/monitor/system/status', json.loads(out)['results'][0]['url'])
        for p in ('C:/Program Files/Git/api/v2/monitor/../cmdb/x', 'C:/Windows/notapi/v2/x'):
            self.assertEqual(self.run_cli('get', 'api', p)[0], cli.EXIT_USAGE, p)

    def test_inventory_cannot_choose_a_local_program(self):
        with open(os.path.join(self.tmp.name, 'inventory.toml'), 'a') as fh:
            fh.write('\n[device.evil]\nhost = "x"\nvendor = "generic"\ntransport = "exec"\n'
                     'exec = ["cat", "creds/fw.pw"]\n')
        calls = []
        with connectors.use('ssh', SimpleNamespace(run=lambda d, c, t: calls.append(d) or Result('', '', 0))):
            self.run_cli('run', 'evil', '-c', 'x')
        self.assertEqual(len(calls), 1, 'every device goes through the ssh transport')

    def test_mask_keeps_input_line_endings(self):
        secret = b'    set password ENC Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5'
        entry = os.path.join(ROOT, 'scripts', 'credveil.py')
        for eol in (b'\n', b'\r\n'):
            raw = os.path.join(self.tmp.name, 'eol.txt')
            with open(raw, 'wb') as fh:
                fh.write(b'line one' + eol + secret + eol)
            with open(raw, 'rb') as fh:
                data = fh.read()
            for args, stdin in (([raw], None), ([], data)):
                p = subprocess.run([sys.executable, '-I', entry, 'mask', '--vendor', 'fortios'] + args,
                                   input=stdin, capture_output=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(p.stdout, b'line one' + eol + b'    set password <masked>' + eol, (eol, args))
        self.assertNotIn('\r', self.run_cli('run', 'fw', '-c', 'x')[1])

    def test_unknown_alias(self):
        rc, _, err = self.run_cli('run', 'nope', '-c', 'x')
        self.assertEqual(rc, cli.EXIT_USAGE)
        self.assertIn('unknown device', err)

    def test_list_shows_no_secret_values(self):
        rc, out, _ = self.run_cli('list')
        self.assertEqual(rc, 0)
        self.assertIn('fw', out)
        self.assertNotIn(PW, out)
        self.assertNotIn(TOKEN, out)

    def test_audit_prints_no_values(self):
        raw = os.path.join(self.tmp.name, 'raw.txt')
        with open(raw, 'w') as fh:
            fh.write('hostname x\n    set password ENC Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5\nplain\n')
        rc, out, _ = self.run_cli('audit', '--vendor', 'fortios', raw)
        self.assertEqual(rc, 0)
        self.assertNotIn('Zm9vYmFy', out)
        self.assertIn('touched lines: 2', out)

    def test_mask_uses_the_device_credentials(self):
        raw = os.path.join(self.tmp.name, 'capture.log')
        with open(raw, 'w') as fh:
            fh.write(f'2026-11-27T10:00:00Z login failed for ro, password was {PW}\nhostname fw-1\n')
        rc, out, err = self.run_cli('mask', raw, '--alias', 'fw')
        self.assertEqual(rc, 0, err)
        self.assertNotIn(PW, out)
        self.assertIn('<masked:known>', out)
        self.assertIn('hostname fw-1', out)

    def test_mask_alias_supplies_the_vendor_rules(self):
        raw = os.path.join(self.tmp.name, 'export.conf')
        with open(raw, 'w') as fh:
            fh.write(PSK_LINE + '\n')
        rc, out, err = self.run_cli('mask', raw, '--alias', 'fw')
        self.assertEqual(rc, 0, err)
        self.assertNotIn('Zm9vYmFy', out)

    def test_mask_without_alias_consults_no_credentials(self):
        raw = os.path.join(self.tmp.name, 'capture.log')
        with open(raw, 'w') as fh:
            fh.write(f'login failed for ro, password was {PW}\n')
        rc, out, _ = self.run_cli('mask', raw)
        self.assertEqual(rc, 0)
        self.assertIn(PW, out)          # rules only; --alias is what adds the device's own values

    def test_mask_withholds_a_file_when_a_known_credential_survives(self):
        from credveil.mask import Masker as RealMasker

        class Stuck(RealMasker):
            def text(self, raw, backstops=True):   # a masker that stops masking: the guard, not a rule
                return raw

        raw = os.path.join(self.tmp.name, 'capture.log')
        with open(raw, 'w') as fh:
            fh.write(f'banner {PW}\n')
        orig, cli.Masker = cli.Masker, Stuck
        try:
            rc, out, err = self.run_cli('mask', raw, '--alias', 'fw')
        finally:
            cli.Masker = orig
        self.assertEqual((rc, out), (cli.EXIT_LEAK, ''))
        self.assertIn('withheld', err)
        self.assertNotIn(PW, err)

    def test_audit_alias_counts_the_device_credentials(self):
        raw = os.path.join(self.tmp.name, 'capture.log')
        with open(raw, 'w') as fh:
            fh.write(f'banner {PW}\nhostname x\n')
        rc, out, err = self.run_cli('audit', raw, '--alias', 'fw')
        self.assertEqual(rc, 0, err)
        self.assertIn('known=1', out)

    def test_summary_counts_both_streams(self):
        rc, _, err = self.run_cli('run', 'noisy', '-c', 'x')
        self.assertEqual(rc, 3)
        self.assertIn('enc=1', err)     # the masking happened on stderr; the summary says so


class SshArgv(unittest.TestCase):
    def test_argv_never_carries_the_password(self):
        d = {'alias': 'fw', 'host': '192.0.2.14', 'user': 'ro', 'password_file': '/x/fw.pw',
             'hostkey': 'SHA256:abc', 'ssh_client': 'plink'}
        orig = ssh.shutil.which
        ssh.shutil.which = lambda n: '/usr/bin/' + n
        try:
            argv, _ = ssh.argv(d, 'cmds.txt', tempfile.gettempdir())
        finally:
            ssh.shutil.which = orig
        self.assertIn('-pwfile', argv)
        self.assertIn('-batch', argv)
        self.assertEqual(argv[argv.index('-hostkey') + 1], 'SHA256:abc')
        self.assertNotIn(PW, ' '.join(argv))

    def test_missing_client_is_a_transport_error(self):
        orig = ssh.shutil.which
        ssh.shutil.which = lambda n: None
        try:
            with self.assertRaises(connectors.TransportError):
                ssh.fingerprints({'host': 'x', 'ssh_client': 'plink'})
        finally:
            ssh.shutil.which = orig

    def test_missing_hostkey_pin_is_a_usage_error(self):
        with self.assertRaises(config.UsageError):
            ssh.argv({'alias': 'fw', 'host': 'x', 'ssh_client': 'plink'}, 'c', tempfile.gettempdir())


if __name__ == '__main__':
    unittest.main()
