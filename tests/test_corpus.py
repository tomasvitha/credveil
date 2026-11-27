"""Corpus of vendor output shapes: every case names what must go and what must stay.

Values are synthetic; the shapes follow real command output (noted per case) or config input
syntax. A leak found in the field becomes a case here first, then a rule. So does over-masking.

Run from the repo root: python -m unittest discover tests
"""
import base64
import os
import sys
import unittest
from typing import NamedTuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from credveil.mask import Masker, mask_any, net_mask  # noqa: E402


class Case(NamedTuple):
    source: str          # the command or config form that produces this text
    vendor: str
    text: str
    secrets: tuple
    keep: tuple = ()


LEAKS = [
    Case('IOS show snmp community', 'ios',
         'Community name: s3cretRO\nCommunity Index: s3cretRO\nCommunity SecurityName: s3cretRO\n'
         'storage-type: nonvolatile        active\n',
         ('s3cretRO',), ('storage-type: nonvolatile',)),
    Case('IOS show crypto isakmp key', 'ios',
         'Keyring      Hostname/Address                            Preshared Key\n\n'
         'default      192.0.2.10                                  PskKey123\n'
         'default      198.51.100.7                                Other9Psk\n',
         ('PskKey123', 'Other9Psk'), ('192.0.2.10', '198.51.100.7', 'Keyring')),
    Case('IOS running-config snmp-server host', 'ios',
         'snmp-server host 10.1.1.1 version 2c s3cretRO\nsnmp-server host 10.1.1.2 traps version 2c Trap5Comm\n'
         'snmp-server host 10.1.1.3 informs version 3 priv v3user\n',
         ('s3cretRO', 'Trap5Comm'), ('10.1.1.1', 'version 3 priv v3user')),
    Case('IOS HSRP authentication', 'ios',
         'interface Vlan10\n standby 1 authentication md5 key-string HsrpKey1\n'
         ' standby 2 authentication HsrpTxt1\n vrrp 3 authentication text VrrpTxt1\n',
         ('HsrpKey1', 'HsrpTxt1', 'VrrpTxt1'), ('standby 1 authentication md5 key-string',)),
    Case('IOS IKEv2 keyring', 'ios',
         'crypto ikev2 keyring K\n peer P\n  address 192.0.2.9\n  pre-shared-key local Local1Psk\n'
         '  pre-shared-key remote Remote1Psk\n',
         ('Local1Psk', 'Remote1Psk'), ('address 192.0.2.9',)),
    Case('IOS SNMPv3 user (input syntax)', 'ios',
         'snmp-server user u grp v3 auth sha AuthPw123 priv aes 128 PrivPw456\n',
         ('AuthPw123', 'PrivPw456'), ('snmp-server user u grp v3 auth sha',)),
    Case('IOS key ids before md5', 'ios',
         'ntp authentication-key 1 md5 NtpKey1 7\n ip ospf message-digest-key 1 md5 7 0822455D0A16\n',
         ('NtpKey1', '0822455D0A16'), ('authentication-key 1 md5', 'message-digest-key 1 md5')),
    Case('IOS autonomous AP wpa-psk', 'ios', ' wpa-psk ascii 0 WifiPass123\n', ('WifiPass123',)),
    Case('AOS-CX SNMPv3 user (input syntax)', 'aos-cx',
         'snmpv3 user u auth sha auth-pass plaintext AuthCx1 priv aes priv-pass plaintext PrivCx1\n',
         ('AuthCx1', 'PrivCx1'), ('snmpv3 user u auth sha',)),
    Case('AOS-CX show running-config json', 'aos-cx',
         '{\n  "password": "Hunter2Json",\n  "psk": "Psk1abc",\n  "name": "core-1"\n}\n',
         ('Hunter2Json', 'Psk1abc'), ('"name": "core-1"',)),
    Case('Comware SNMPv3 user (input syntax)', 'comware',
         'snmp-agent usm-user v3 u g authentication-mode sha AuthCw1 privacy-mode aes128 PrivCw1\n',
         ('AuthCw1', 'PrivCw1'), ('snmp-agent usm-user v3 u g',)),
    Case('aligned or labelled values', 'ios',
         'neighbor 192.0.2.2 password\tBgpTab1\nneighbor 192.0.2.3  password  BgpDbl1\n'
         'Password: Hunter2Echo\nsecret: Hunter2Col\npassword=Hunter2Eq\n',
         ('BgpTab1', 'BgpDbl1', 'Hunter2Echo', 'Hunter2Col', 'Hunter2Eq'), ('neighbor 192.0.2.3',)),
    Case('quoted value with spaces', 'fortios', '    set password "Pl@in Pw 99"\n', ('Pl@in', 'Pw 99')),
    Case('Junos curly with SECRET-DATA', 'junos',
         'authentication-key "$9$Hk5FCtO-dsYoaREyKvL7-dVwYgJGi.5Q"; ## SECRET-DATA\n',
         ('Hk5FCtO', 'dVwYgJGi', 'SECRET-DATA'), ('authentication-key',)),
    Case('shell env and headers', 'generic',
         'export DB_PASSWORD=Hunter2Env\n$env:API_TOKEN = "Tok3nPwsh"\nAuthorization: Bearer abcDEF123ghiJKL456\n'
         'X-Api-Key: Key9ApiXyz\npassword: YamlPw1\n',
         ('Hunter2Env', 'Tok3nPwsh', 'abcDEF123ghiJKL456', 'Key9ApiXyz', 'YamlPw1'), ('export DB_PASSWORD=',)),
    Case('Zabbix/Kimai-style JSON in text', 'generic',
         '{"result": {"tls_psk": "0123abcdPsk", "api_token": "Kimai7Tok", "host": "srv1"}}\n',
         ('0123abcdPsk', 'Kimai7Tok'), ('"host": "srv1"',)),
    Case('PuTTY key file', 'generic',
         'PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\nPrivate-Lines: 1\n'
         'AAAAIPlantedPuttyPrivLine48charsAbCdEf0123456789xy\nPrivate-MAC: 0f' + '1a' * 31 + '\n',
         ('PlantedPuttyPriv',), ('Encryption: none',)),
]

# Text that must come out unchanged (diagnostics the masking used to eat).
UNCHANGED = [
    Case('description free text', 'ios',
         'interface Po1\n description password reset portal uplink\n description key account link\n', ()),
    Case('show crypto key mypubkey', 'ios', 'R1#show crypto key mypubkey rsa\n', ()),
    Case('certificate serial and fingerprint', 'ios',
         '  Certificate Serial Number (hex): 4F1A2B3C4D5E6F708192A3B4C5D6E7F8\n'
         '  SHA1 Fingerprint: 0123456789ABCDEF0123456789ABCDEF01234567\n', ()),
    Case('git log', 'generic', 'commit 3f2a9c1d8b7e6f5a4c3b2a19087f6e5d4c3b2a19\n', ()),
    Case('tunnel key length', 'fortios', '  dec: spi=8a1b2c3d esp=aes key=16\n', ()),
    Case('aaa and syslog prose', 'ios',
         'aaa authentication login default local\n%SEC-6-IPACCESSLOGP: auth failed for user bob\n', ()),
    Case('shell without secrets', 'generic',
         'export PATH=/usr/bin\nmax_tokens: 100\npassword_file = "creds/fw1.pw"\n', ()),
]


class Corpus(unittest.TestCase):
    def test_leaks_masked_and_context_kept(self):
        for c in LEAKS:
            with self.subTest(c.source):
                out = Masker(c.vendor).text(c.text)
                for s in c.secrets:
                    self.assertNotIn(s, out, f'{c.source}: secret survived\n{out}')
                for k in c.keep:
                    self.assertIn(k, out, f'{c.source}: over-masked\n{out}')

    def test_diagnostics_unchanged(self):
        for c in UNCHANGED:
            with self.subTest(c.source):
                self.assertEqual(Masker(c.vendor).text(c.text), c.text)


class NetHashes(unittest.TestCase):
    """The output net on arbitrary text: every crypt-like form goes whole."""

    def test_hash_forms(self):
        for line, tail in (
                ('enable secret 9 $9$nhEmQVczB7dqsO$X.HsgL6x1il0RxkOSSvyQYwucySCt7qFm4v7pqCxkKM', 'X.Hsg'),
                ('enable secret 8 $8$dsYGNam3K1SIJO$7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs', '7nv/35M'),
                ('authentication-key "$9$Hk5FCtO-dsYoaREyKvL7-dVwYgJGi.5Q";', 'dVwYgJGi'),
                (' password cipher $c$3$PlantedCipherBody0123456789abcdef==', 'PlantedCipher')):
            self.assertNotIn(tail, net_mask(line), line)

    def test_ppk_lines(self):
        body = base64.b64encode(bytes(range(36))).decode()          # 48 chars, an ed25519 line
        out = net_mask(f'Private-Lines: 1\n{body}\nPrivate-MAC: x\n')
        self.assertNotIn(body, out)
        self.assertIn('Private-MAC', out)


class Detection(unittest.TestCase):
    def test_exports_detected(self):
        for head, secret in (('#config-version=FGT60F-7.4.4-FW-build2662\nconfig system admin\n'
                              '    edit "a"\n        set password Plain1Pw\n', 'Plain1Pw'),
                             ('# 2026-11-27 10:00:00 by RouterOS 7.16\n/ppp secret\nadd name=a password=Ros1Pw\n',
                              'Ros1Pw'),
                             ('!Version ArubaOS-CX GL.10.13\nradius-server host 10.1.1.1 key plaintext CxRad1\n',
                              'CxRad1')):
            self.assertNotIn(secret, mask_any(head))

    def test_undetected_text_gets_only_the_net(self):
        src = 'password = read_pw()\nkey = "abc"\n'
        self.assertEqual(mask_any(src), src)


if __name__ == '__main__':
    unittest.main()
