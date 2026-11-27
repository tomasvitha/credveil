"""Unknown systems, shells and logs: `NAME=value` / `name: value` with a secret-looking name.

The default pack. Covers env assignments (`export DB_PASSWORD=…`, `$env:API_TOKEN = …`),
YAML/INI-style `password: …`, and log fields; JSON pairs and auth headers come from the generic
rules every pack gets.
"""
from ..mask.syntax import AssignRules
from . import Pack, register

PARAMS = AssignRules(
    keys=frozenset({'password', 'passwd', 'pwd', 'secret', 'token', 'psk', 'passphrase',
                    'community', 'apikey', 'api_key', 'api-key', 'private_key', 'private-key'}),
    contains=('password', 'passwd', 'secret', 'token', 'api_key', 'apikey', 'api-key',
              'private_key', 'private-key', 'passphrase', 'credential'),
    not_secret=frozenset({'token_type', 'tokens', 'secret_name', 'password_file', 'token_file',
                          'password-policy', 'password_policy', 'max_tokens'}),
    separators='=:',
)


class Lines:
    def line(self, line, counts):
        return PARAMS.mask(line, counts)


register(Pack(
    name='generic',
    aliases=('shell', 'bash', 'powershell', 'pwsh', 'linux', 'windows'),
    line_masker=Lines,
))
