"""Credential families: shapes that name a secret by themselves, whatever the system.

A JWT, a platform token or a password hash needs no vendor context: the prefix or the `$`
layout is the evidence. These cases were leaks first (a log line, an export, a REST body) and
each one also pins what must survive, because over-masking hides diagnostics just as badly.

Run from the repo root: python -m unittest discover tests
"""
import base64
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from credveil.mask import Masker, net_mask

JWT = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.'
       'dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U')
URLSAFE = '8fJ2kLmQ_9xYzAbC-dEfGhIjKlMnOpQrStUvWxYz0123456789'

# Planted values are assembled from parts, like the corpus fixtures: a literal would be scanned
# as a real credential by the hosting service (and the rules under test would then be tested by
# a string that is no longer there). `_fixture()` below refuses a case that lost its secret.
GH = 'gh' + 'p_' + '16C7e42F292c6912E7710c838347Ae178B4a'
GH_FINE = 'github' + '_pat_' + '11ABCDEFG0abcdefghijKlMnOpQrStUvWx'
GITLAB = 'glp' + 'at-' + 'xYz9AbCdEfGh12345678'
SLACK = 'xox' + 'b-' + '123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx'
STRIPE = 'sk' + '_live_' + '51H8YxKLMnOpQrStUvWxYzAbCdEfGhIjKlMnOp'
GOOGLE = 'AI' + 'za' + 'SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY'
AWS = 'AK' + 'IA' + 'IOSFODNN7EXAMPLE'
OPENAI = 'sk' + '-' + '9fJ2kLmQ8xYzAbCdEfGhIjKlMnOpQrStUvWxYz0123'

# (label, text, the value that must go)
TOKENS = (
    ('github', f'push failed token={GH}', GH),
    ('github fine-grained', f'TOKEN={GH_FINE}', GH_FINE),
    ('gitlab', f'remote: {GITLAB} rejected', GITLAB),
    ('slack', f'session {SLACK}', SLACK),
    ('stripe', f'export STRIPE={STRIPE}', STRIPE),
    ('google', f'key {GOOGLE} used', GOOGLE),
    ('aws key id', f'aws_access_key_id = {AWS}', AWS),
    ('openai style', f'client {OPENAI}', OPENAI),
)

# (label, text, secret fragment that must go, scheme that must stay)
HASHES = (
    ('argon2id', 'stored $argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHRzb21lc2FsdA$RdescudvJCsgt3ub+b', 'RdescudvJCsgt3ub', 'argon2id'),
    ('django pbkdf2', 'value=pbkdf2_sha256$600000$saltsaltsalt$Kj8h2Lm9Qp0Rs1Tu2Vw3Xy4Za5Bc6D', 'Kj8h2Lm9Qp0Rs1', 'pbkdf2_sha256'),
    ('scrypt', 'value: $scrypt$ln=16,r=8,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG', 'RdescudvJCsgt3ub', 'scrypt'),
    ('ldap ssha', 'value: {SSHA}5en6G6MezRroT3XKqkdPOmY/BfQ=', '5en6G6MezRroT3XK', '{SSHA}'),
    ('ldap md5', 'value: {MD5}X03MO1qnZdYdgyfeuILPmQ==', 'X03MO1qnZdYdgyfeu', '{MD5}'),
)


class Jwt(unittest.TestCase):
    def test_whole_token_goes_not_one_segment(self):
        out = Masker('cli').text(f'2026-11-27T10:00:00Z INFO auth ok, session {JWT}\n')
        self.assertIn('<masked:jwt>', out)
        self.assertNotIn('eyJ', out)
        self.assertNotIn('dozjgNr', out)
        self.assertIn('auth ok', out)

    def test_json_value_and_net(self):
        self.assertNotIn('eyJ', Masker('fortios').text(f'{{"note": "{JWT}"}}\n'))
        self.assertNotIn('eyJ', net_mask(f'log: {JWT}\n'))


class Tokens(unittest.TestCase):
    def test_every_family_masked_in_every_pack(self):
        for vendor in ('cli', 'generic', 'fortios', 'routeros'):
            for label, text, secret in TOKENS:
                with self.subTest(f'{vendor}: {label}'):
                    self.assertIn(secret, text, 'fixture lost its secret')
                    self.assertNotIn(secret, Masker(vendor).text(text), label)

    def test_net_masks_them_too(self):
        for label, text, secret in TOKENS:
            with self.subTest(label):
                self.assertIn(secret, text, 'fixture lost its secret')
                self.assertNotIn(secret, net_mask(text), label)


class Hashes(unittest.TestCase):
    def test_digest_goes_scheme_stays(self):
        for label, text, secret, scheme in HASHES:
            for vendor in ('cli', 'generic'):
                with self.subTest(f'{vendor}: {label}'):
                    out = Masker(vendor).text(text)
                    self.assertNotIn(secret, out, label)
                    self.assertIn(scheme, out, f'{label}: the scheme is diagnostic')

    def test_net_masks_them_too(self):
        for label, text, secret, _ in HASHES:
            with self.subTest(label):
                self.assertNotIn(secret, net_mask(text), label)


class Urlsafe(unittest.TestCase):
    def test_urlsafe_blob_masked_whole(self):
        for vendor in ('generic', 'fortios'):
            with self.subTest(vendor):
                out = Masker(vendor).text(f'SESSION={URLSAFE}\n')
                self.assertNotIn('8fJ2kLmQ', out)
                self.assertIn('<masked:b64>', out)

    def test_net_masks_urlsafe_blob(self):
        self.assertNotIn(URLSAFE, net_mask(f'session: {URLSAFE}\n'))

    def test_standard_base64_still_masked(self):
        tok = base64.b64encode(b'PlantedRandomBlobXyz0123456789abcdefABCDEF').decode()
        self.assertNotIn(tok, Masker('generic').text(f'value {tok} end'))


class UrlUserinfo(unittest.TestCase):
    def test_password_in_url_masked_user_and_host_kept(self):
        line = 'GET https://api:p4ssw0rd-Secret@api.example.com/v1/x'
        out = Masker('generic').text(line)
        self.assertNotIn('p4ssw0rd-Secret', out)
        self.assertIn('https://api:', out)
        self.assertIn('@api.example.com/v1/x', out)


class OverMasking(unittest.TestCase):
    """The other half: diagnostic text must come out byte-identical."""

    LINES = (
        'GET /api/v2/monitor/system/interface/select?vdom=root',
        '  SHA1 Fingerprint: 0123456789ABCDEF0123456789ABCDEF01234567',
        '  Certificate Serial Number (hex): 4F1A2B3C4D5E6F708192A3B4C5D6E7F8',
        'commit 3f2a9c1e0b7d4a6f8e5c2b1a0d9e8f7c6b5a4d3e',
        'pbkdf2_iterations = 260000',
        'hash = sha256(x)',
        'token_type = bearer',
        'name=S2S-BRANCH serial=FGVM00TM00000001 mac 00:0c:29:ab:cd:ef',
        'ssh-rsa AAAAB3NzaC1yc2E test@host',
    )
    SOURCE = ('password = read_pw()\nkey = "abc"\nhash = sha256(x)\n'
              'url = f"{scheme}://{user}:{pw}@{host}/x"\n')

    def test_unchanged_in_every_pack(self):
        for vendor in ('generic', 'fortios', 'ios', 'routeros', 'cli'):
            for line in self.LINES:
                with self.subTest(f'{vendor}: {line}'):
                    self.assertEqual(Masker(vendor).text(line), line)

    def test_unchanged_in_the_net(self):
        for line in self.LINES:
            with self.subTest(line):
                self.assertEqual(net_mask(line), line)
        self.assertEqual(net_mask(self.SOURCE), self.SOURCE)


class Idempotent(unittest.TestCase):
    def test_masking_twice_changes_nothing(self):
        text = '\n'.join([f'value: {h[1]}' for h in HASHES] +
                         [f'session {JWT}', 'GET https://u:pw-123456@h/x',
                          f'SESSION={URLSAFE}']) + '\n'
        once = Masker('generic').text(text)
        self.assertEqual(Masker('generic').text(once), once)
        self.assertEqual(net_mask(net_mask(text)), net_mask(text))


if __name__ == '__main__':
    unittest.main()
