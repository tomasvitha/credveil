# Extending credveil

Everything about one system lives in one file under `credveil/packs/`. A module there
registers a `Pack` at import and is discovered automatically, so the engine, the CLI and the
hooks need no change.

## A new pack

```python
# credveil/packs/zabbix.py
from ..mask.syntax import AssignRules
from . import ApiProfile, Pack, fingerprints, register

PARAMS = AssignRules(keys=frozenset({'password', 'tls_psk', 'snmpv3_authpassphrase'}),
                     suffixes=('_passphrase', '_psk'), separators='=:')


class Lines:                      # one instance per output stream; keep per-stream state here
    def line(self, line, counts):
        return PARAMS.mask(line, counts)


register(Pack(
    name='zabbix', aliases=('zbx',),
    line_masker=Lines,
    json_secret_keys=PARAMS.keys,                      # masks these keys in REST JSON bodies
    fingerprints=fingerprints(r'^# Zabbix'),           # optional: lets the output net recognise raw dumps
    api=ApiProfile(prefixes=('/api/',), auth_header='Authorization', auth_scheme='Bearer'),
))
```

Every pack gets the vendor-neutral rules on top: PEM and PuTTY keys, `ENC`, crypt hashes,
auth headers, JSON `"key": "value"` pairs with secret-looking keys, long hex and base64 blobs,
and the known credentials.

## Building blocks (`credveil/mask/syntax.py`)

| Block | For | Data you give it |
|---|---|---|
| `KeywordRules` | `keyword [type] value` CLIs | secret words, type tokens, `not_after`, `needs_next`, free-text line prefixes |
| `AssignRules` | `key=value`, `key: value` | key names, suffixes, substrings, exceptions, separators |
| `TableMasker` | aligned tables with a secret column | column titles |
| `RegexRule` | one positional form nothing else expresses | a pattern and the group to mask |

A pack that needs per-line state, like a config path or a menu, keeps it in its `Lines`
object (see `fortios.py`, `routeros.py`). CLI context such as `--vdom` is a `wrap_commands`
function on the pack.

## Tests come first

Add the output shape to `tests/test_corpus.py`. Write the secret that must go into `LEAKS`
and the diagnostic text that must stay into `keep`; a harmless line that must come out
byte-identical goes into `UNCHANGED`. Use synthetic values and the real command's shape, and
name the command in `source`. Then write the rule, and run `python3 -m unittest discover tests`.

## Another agent runtime

`credveil.policy` (guard decisions) and `credveil.mask.mask_any` (output net) know nothing
about hooks. A new runtime needs one module next to `credveil/adapters/claude_code.py`: it
reads the runtime's hook payload, maps its tool names to shell/read/search/write, and answers
in that runtime's protocol.
