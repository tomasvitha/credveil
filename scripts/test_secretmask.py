"""Tests for secretmask.py on synthetic samples.  Run: python -m unittest -v (in this folder).

Every secret below is planted and fake. Each fixture lists what must disappear (SECRETS) and
what must survive (KEEP) - over-masking that eats the diagnostic content is a failure too.
"""
import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import secretmask as sm  # noqa: E402

FORTIOS_SHOW = '''\
config system admin
    edit "admin"
        set accprofile "super_admin"
        set vdom "root"
        set password ENC SH2UGxhbnRlZEFkbWluSGFzaFBsYW50ZWRBZG1pbkhhc2g=
    next
end
config vpn ipsec phase1-interface
    edit "S2S-TEST"
        set interface "wan1"
        set authmethod psk
        set remote-gw 203.0.113.10
        set psksecret ENC Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A=
    next
end
config system snmp community
    edit 1
        set name "PlantedCommunity1"
        config hosts
            edit 1
                set ip 10.9.9.9 255.255.255.255
            next
        end
    next
end
config user ldap
    edit "AD"
        set server "10.0.0.5"
        set password ENC AbCdEf123456GhIjKl789012MnOpQr345678StUv==
    next
end
config system interface
    edit "port1"
        set ip 192.0.2.1 255.255.255.0
        set alias "uplink-isp"
    next
end
config vpn certificate local
    edit "fw-cert"
        set password ENC Qk1sZ3d4eXo5ODc2NTQzMjFhYmNkZWZnaGlqa2w=
        set private-key "-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQIPlantedPrivBody1
AgIIADAMBggqhkiG9w0CCQUAMBQGCCqGSIb3DQMHBAgPlantedPrivBody2abc
-----END ENCRYPTED PRIVATE KEY-----"
        set certificate "-----BEGIN CERTIFICATE-----
MIIDdzCCAl+gAwIBAgIEPlantedCertBody1xyz
-----END CERTIFICATE-----"
    next
end
'''
FORTIOS_SHOW_SECRETS = [
    'SH2UGxhbnRlZEFkbWluSGFzaFBsYW50ZWRBZG1pbkhhc2g=',
    'Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3A=',
    'AbCdEf123456GhIjKl789012MnOpQr345678StUv', 'Qk1sZ3d4eXo5ODc2NTQzMjFhYmNkZWZnaGlqa2w',
    'PlantedPrivBody1', 'PlantedPrivBody2', 'PlantedCertBody1']
FORTIOS_SHOW_KEEP = ['edit "S2S-TEST"', 'set remote-gw 203.0.113.10', 'set authmethod psk',
                     'set server "10.0.0.5"', 'set ip 10.9.9.9 255.255.255.255',
                     'set alias "uplink-isp"', 'set accprofile "super_admin"', 'edit "fw-cert"',
                     'set name "PlantedCommunity1"']  # v1/v2c community: not a secret (design decision)

FORTIOS_TUNNEL_LIST = '''\
list all ipsec tunnel in vd 3
name=S2S-TEST ver=2 serial=1 203.0.113.1:0->203.0.113.10:0 tun_id=203.0.113.10
bound_if=5 lgwy=static/1 tun=intf mode=auto/1 encap=none/552 options[0228]=npu frag-rfc
  dec: spi=8a1b2c3d esp=aes key=32 0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0
       ah=sha256 key=32 a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90
  enc: spi=c0ffee12 esp=aes key=16 00112233445566778899aabbccddeeff
       ah=sha1 key=20 deadbeefdeadbeefdeadbeefdeadbeefdeadbe01
  npu_flag=00 npu_rgwy=203.0.113.10 npu_lgwy=203.0.113.1 npu_selid=0 dec_npuid=0 enc_npuid=0
'''
TUNNEL_SECRETS = ['0f1e2d3c4b5a6978', 'a1b2c3d4e5f60718', '00112233445566778899aabbccddeeff',
                  'deadbeefdeadbeefdeadbeef']
TUNNEL_KEEP = ['spi=8a1b2c3d', 'spi=c0ffee12', 'esp=aes key=32', 'name=S2S-TEST',
               'npu_rgwy=203.0.113.10']

FORTIOS_IKE_DEBUG = '''\
ike 0:S2S-TEST:123: SKEYSEED=4f3c2a1b0e9d8c7b6a5f4e3d2c1b0a99
ike 0:S2S-TEST:123: PSK 3a9f00aa11
ike 0: IPsec phase 1 error, probable pre-shared key mismatch
ike 0:S2S-TEST:123: dec 2D3C4B5A69788796A5B4C3D2E1F00F1E2D3C4B5A6978879600112233
ike 0:S2S-TEST:123: responder: main mode get 1st message...
'''
IKE_SECRETS = ['4f3c2a1b0e9d8c7b', '3a9f00aa11', '2D3C4B5A69788796A5B4']
IKE_KEEP = ['pre-shared key mismatch', 'responder: main mode get 1st message', 'ike 0:S2S-TEST:123:']

IOS = '''\
hostname R1
enable secret 9 $9$abcdefg$hijkPlantedEnable
username admin privilege 15 secret 9 $9$xyz$uvwPlantedUser
username ops password 7 0822455D0A16
crypto isakmp key PlantedIsakmpKey address 0.0.0.0
crypto pki certificate chain TP-self-signed-1
 certificate self-signed 01
  3082022B 30820194 A0030201 02020101 300D0609
  2A864886 F70D0101 05050030 31312F30 2D060355
  	quit
interface GigabitEthernet0/0
 description WAN uplink
 ip address 192.0.2.1 255.255.255.0
 ip ospf message-digest-key 1 md5 7 0822455D0A16BEEF
router bgp 65001
 neighbor 192.0.2.2 password 7 13061E010803
snmp-server community s3cretRO RO 10
snmp-server user mon grp v3 auth sha 0x1a2b3c4d5e6f7a8b9c0d priv aes 128 0x0d0c0b0a09080706
tacacs server T1
 address ipv4 10.0.0.5
 key 7 PlantedTacacs7
'''
IOS_SECRETS = ['PlantedEnable', 'PlantedUser', '0822455D0A16', 'PlantedIsakmpKey', '3082022B',
               '13061E010803', 's3cretRO', '0x1a2b3c4d5e6f7a8b9c0d', 'PlantedTacacs7']
IOS_KEEP = ['hostname R1', 'description WAN uplink', 'ip address 192.0.2.1 255.255.255.0',
            'neighbor 192.0.2.2', 'address ipv4 10.0.0.5', 'interface GigabitEthernet0/0']

AOSCX = '''\
hostname cx-core-1
user admin group administrators password ciphertext AQBapPlantedCxBlob1234==
radius-server host 10.1.1.1 key ciphertext AQBapPlantedRad99==
snmp-server community PlantedCxComm
interface 1/1/1
    description to-fw
    ip address 10.20.0.1/30
'''
AOSCX_SECRETS = ['PlantedCxBlob', 'PlantedRad99', 'PlantedCxComm']
AOSCX_KEEP = ['hostname cx-core-1', 'radius-server host 10.1.1.1', 'description to-fw',
              'ip address 10.20.0.1/30']

COMWARE = '''\
sysname hp-sw1
local-user admin class manage
 password hash $h$6$PlantedComwareHash==
snmp-agent community read cipher $c$3$PlantedCipher==
interface Vlan-interface10
 ip address 10.10.10.1 255.255.255.0
'''
COMWARE_SECRETS = ['PlantedComwareHash', 'PlantedCipher']
COMWARE_KEEP = ['sysname hp-sw1', 'local-user admin class manage', 'ip address 10.10.10.1']

JUNOS = '''\
set system host-name mx1
set system root-authentication encrypted-password "$6$abc$PlantedJunosHash"
set protocols bgp group X authentication-key "$9$PlantedNine"
set snmp community PlantedJunosComm authorization read-only
set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.1/30
'''
JUNOS_SECRETS = ['PlantedJunosHash', 'PlantedNine', 'PlantedJunosComm']
JUNOS_KEEP = ['set system host-name mx1', 'ge-0/0/0 unit 0 family inet address 198.51.100.1/30']

ROUTEROS = '''\
# 2026-11-27 by RouterOS 7.16
/ppp secret
add name=vpn1 password=PlantedRos1 service=l2tp
/interface wireless security-profiles
set [ find default=yes ] wpa2-pre-shared-key=PlantedWifi1 mode=dynamic-keys
/snmp community
add addresses=10.0.0.0/8 name=PlantedRosComm
/ip address
add address=10.0.0.1/24 interface=bridge
/interface wireguard
add listen-port=13231 name=wg0 private-key="PlantedWgPriv="
'''
ROS_SECRETS = ['PlantedRos1', 'PlantedWifi1', 'PlantedRosComm', 'PlantedWgPriv']
ROS_KEEP = ['name=vpn1', 'service=l2tp', 'address=10.0.0.1/24 interface=bridge', 'addresses=10.0.0.0/8',
            'listen-port=13231']



class Fixtures(unittest.TestCase):
    def check(self, vendor, text, secrets, keep):
        m = sm.Masker(vendor)
        out = m.text(text)
        for s in secrets:
            self.assertNotIn(s, out, f'{vendor}: secret survived: {s}\n{out}')
        for k in keep:
            self.assertIn(k, out, f'{vendor}: over-masked, lost: {k}\n{out}')
        return out, m

    def test_fortios_show(self):
        out, m = self.check('fortios', FORTIOS_SHOW, FORTIOS_SHOW_SECRETS, FORTIOS_SHOW_KEEP)
        self.assertIn('<pem:certificate sha=', out)
        self.assertIn('<masked:encrypted-private-key>', out)
        self.assertEqual(m._ctx, [], 'config path stack not balanced')

    def test_fortios_tunnel_list(self):
        self.check('fortios', FORTIOS_TUNNEL_LIST, TUNNEL_SECRETS, TUNNEL_KEEP)

    def test_fortios_ike_debug(self):
        self.check('fortios', FORTIOS_IKE_DEBUG, IKE_SECRETS, IKE_KEEP)

    def test_ios(self):
        out, _ = self.check('ios', IOS, IOS_SECRETS, IOS_KEEP)
        self.assertIn('<hexdump:2 lines>', out)

    def test_aoscx(self):
        self.check('aos-cx', AOSCX, AOSCX_SECRETS, AOSCX_KEEP)

    def test_comware(self):
        self.check('comware', COMWARE, COMWARE_SECRETS, COMWARE_KEEP)

    def test_junos(self):
        self.check('junos', JUNOS, JUNOS_SECRETS, JUNOS_KEEP)

    def test_routeros(self):
        self.check('routeros', ROUTEROS, ROS_SECRETS, ROS_KEEP)

    def test_generic_catches_vendor_neutral_forms(self):
        # unknown vendor: PEM, ENC, crypt hashes and tunnel keys still go
        text = FORTIOS_SHOW + FORTIOS_TUNNEL_LIST
        out = sm.Masker('generic').text(text)
        for s in ['PlantedPrivBody1', 'PlantedCertBody1', 'SH2UGxhbnRlZEFkbWlu',
                  '00112233445566778899aabbccddeeff']:
            self.assertNotIn(s, out)

    def test_unknown_vendor_rejected(self):
        with self.assertRaises(ValueError):
            sm.Masker('netscreen')


class Blocks(unittest.TestCase):
    def test_unterminated_pem_never_leaks(self):
        out = sm.Masker('generic').text('x\n-----BEGIN RSA PRIVATE KEY-----\nPlantedTruncated\n')
        self.assertNotIn('PlantedTruncated', out)
        self.assertIn('<masked:unterminated-rsa-private-key>', out)

    def test_inline_pem_in_one_line(self):
        line = '"cert": "-----BEGIN PRIVATE KEY-----\\nPlantedInline\\n-----END PRIVATE KEY-----"'
        out = sm.Masker('generic').text(line)
        self.assertNotIn('PlantedInline', out)

    def test_trailing_newline_preserved(self):
        m = sm.Masker('generic')
        self.assertEqual(m.text('a\nb\n'), 'a\nb\n')
        self.assertEqual(m.text('a\nb'), 'a\nb')

    def test_b64_backstop(self):
        tok = base64.b64encode(b'PlantedRandomBlobXyz0123456789abcdefABCDEF').decode()
        out = sm.Masker('generic').text(f'value {tok} end')
        self.assertNotIn(tok, out)
        self.assertIn('<masked:b64>', out)

    def test_b64_backstop_spares_paths(self):
        line = 'GET /api/v2/monitor/system/interface/select?vdom=root'
        self.assertEqual(sm.Masker('generic').text(line), line)

    def test_numeric_tables_are_not_hexdumps(self):
        text = 'port1   1500   1500   1500\n  10  20  30  40\n'
        self.assertEqual(sm.Masker('generic').text(text), text)

    def test_addressing_never_masked(self):
        # Design decision: IPs are wanted in output; only credentials and certificates go.
        text = ('10.255.0.2        1   Full/ -         00:00:35    169.254.10.2    vlink-br0\n'
                'S       0.0.0.0/0 [10/0] via 192.168.1.254, port1, [1/0]\n'
                'B       2001:0db8:85a3:0000:0000:8a2e:0370:7334/128 [200/0] via fe80::a00:27ff:fe4e:66a1, port3\n'
                'name=S2S-BRANCH ver=2 serial=1 203.0.113.34:4500->198.51.100.9:4500 tun_id6=::10.0.0.1\n'
                '  dst: 0:192.168.50.0/255.255.255.0:0\n'
                '  dec: spi=8a1b2c3d esp=aes key=16\n'
                'hook=post dir=org act=snat 192.168.1.10:51234->8.8.8.8:443(198.51.100.9:51234)\n'
                '10.1.1.1 0 00:0c:29:ab:cd:ef port1  mac 00-09-0f-09-00-01  serial FGVM00TM00000001\n'
                'fe80::20c:29ff:feab:cdef  2001:db8:9000:1::1  ::ffff:10.0.0.5  100.64.0.1 255.255.255.0\n')
        for vendor in ('generic', 'fortios', 'ios', 'routeros'):
            self.assertEqual(sm.Masker(vendor).text(text), text, vendor)
        self.assertEqual(sm.net_mask(text, []), text)


class Known(unittest.TestCase):
    PW = 'Sup3rS3cret-Pw!'

    def test_known_secret_masked_in_all_encodings(self):
        b64 = base64.b64encode(self.PW.encode()).decode()
        m = sm.Masker('fortios', known=[self.PW])
        out = m.text(f'login {self.PW}\nauth {b64}\nurl ?p=Sup3rS3cret-Pw%21\n')
        self.assertNotIn(self.PW, out)
        self.assertNotIn(b64.rstrip('='), out)
        self.assertNotIn('Sup3rS3cret-Pw%21', out)
        self.assertEqual(m.leaks(out), [])

    def test_leaks_reports_line_numbers_only(self):
        m = sm.Masker('generic', known=[self.PW])
        self.assertEqual(m.leaks(f'a\nb {self.PW}\nc'), [2])


class Json(unittest.TestCase):
    def test_cmdb_body(self):
        body = {'results': [{'name': 'S2S', 'psksecret': 'ENC Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5',
                             'remote-gw': '203.0.113.10', 'nested': {'token': 'PlantedTok123'},
                             'comment': 'cert -----BEGIN PRIVATE KEY-----\nPlantedJ\n-----END PRIVATE KEY-----'}],
                'status': 'success'}
        m = sm.Masker('fortios')
        out = json.dumps(sm.mask_json(body, m))
        for s in ['Zm9vYmFy', 'PlantedTok123', 'PlantedJ']:
            self.assertNotIn(s, out)
        for k in ['203.0.113.10', '"S2S"', '"success"']:
            self.assertIn(k, out)


class Identity(unittest.TestCase):
    """FP-1 (2026-11-27): user and group names pass; only secret forms are masked."""
    H32 = '9f' * 16                                   # a SAML-style 32-hex user id, built at runtime
    CRYPT = '$6$' + 'saltsalt' + '$' + 'Q' * 43         # crypt shape, built at runtime

    def test_json_identity_fields_pass(self):
        body = {'results': [{'xauthuser': self.H32, 'user': 'alice', 'xauthgroup': 'grp_vpn_users',
                             'msg': f'install IPsec SA key {self.H32}', 'psksecret': 'whatever'}]}
        r = sm.mask_json(body, sm.Masker('fortios'))['results'][0]
        self.assertEqual(r['xauthuser'], self.H32)
        self.assertEqual(r['user'], 'alice')
        self.assertEqual(r['xauthgroup'], 'grp_vpn_users')
        self.assertNotIn(self.H32, r['msg'])            # same value outside an identity field: masked
        self.assertEqual(r['psksecret'], sm.MASK)

    def test_json_identity_field_still_masks_secret_forms(self):
        r = sm.mask_json({'user': self.CRYPT, 'username': 'ENC ' + 'Ab1' * 10}, sm.Masker('generic'))
        self.assertNotIn('QQQQ', r['user'])
        self.assertNotIn('Ab1Ab1', r['username'])

    def test_text_identity_context_passes(self):
        for line in (f'xauthuser="{self.H32}" remip=198.51.100.7', f'  XAUTH user: {self.H32}',
                     f'user={self.H32} group=x', f'"xauthuser": "{self.H32}"'):
            self.assertEqual(sm.Masker('fortios').text(line), line, line)

    def test_summary_lists_only_real_hits(self):
        m = sm.Masker('fortios')
        m.text(f'xauthuser={self.H32}\nplain line')
        self.assertEqual(m.summary(), 'nothing')

    def test_text_hex_elsewhere_still_masked(self):
        for line in (f'  dec: spi=8a1b2c3d esp=aes key=16 {self.H32}', f'blob {self.H32}',
                     f'user=alice token {self.H32}'):
            self.assertNotIn(self.H32, sm.Masker('fortios').text(line), line)


class Net(unittest.TestCase):
    def test_source_code_untouched(self):
        src = 'password = read_pw()\nkey = "abc"\nsecret_words = {"psk"}\nhash = sha256(x)\n'
        self.assertEqual(sm.net_mask(src), src)

    def test_git_hashes_untouched(self):
        log = 'commit 3f2a9c1e0b7d4a6f8e5c2b1a0d9e8f7c6b5a4d3e\n'
        self.assertEqual(sm.net_mask(log), log)

    def test_net_masks_unambiguous_forms(self):
        text = (FORTIOS_SHOW + FORTIOS_TUNNEL_LIST +
                'root:$6$saltsalt$PlantedShadowHashPlantedShadowHash01:19000:0\n')
        out = sm.net_mask(text, known=['PlantedCommunity1'])
        for s in ['SH2UGxhbnRlZEFkbWlu', 'PlantedPrivBody1', '00112233445566778899aabbccddeeff',
                  'PlantedShadowHash', 'PlantedCommunity1']:
            self.assertNotIn(s, out)
        self.assertIn('PlantedCertBody1', out)  # certificates are public; the net leaves them

    def test_lone_begin_does_not_swallow_output(self):
        begin = '-----BEGIN RSA ' + 'PRIVATE KEY-----'
        text = f'src/x.py:12: if line.startswith("{begin}"):\nsrc/x.py:13:     return MASK\nnext line\n'
        out = sm.net_mask(text)
        self.assertIn('src/x.py:13:     return MASK', out)
        self.assertIn('next line', out)

    def test_grep_prefixed_key_body_masked(self):
        body = base64.b64encode(bytes(range(48))).decode()  # a 64-char key-body line
        out = sm.net_mask(f'k.pem:2:{body}\nk.pem:3:done\n')
        self.assertNotIn(body, out)
        self.assertIn('k.pem:3:done', out)

    def test_short_known_values_ignored(self):
        self.assertEqual(sm.net_mask('port 22 open', known=['22']), 'port 22 open')


if __name__ == '__main__':
    unittest.main()
