"""The streaming masker: multi-line blocks, then the vendor pack, then the generic rules."""
import re
from collections import Counter

from .. import packs
from . import generic as g


class Masker:
    """One instance per output stream; it keeps block and config-path state across lines.

        m = Masker('fortios', known=[password, token])
        clean = m.text(raw)       # m.counts says what was masked
        m.leaks(clean)            # line numbers where a known secret survived
    """

    def __init__(self, vendor='generic', known=()):
        self.pack = packs.get(vendor)
        self.known = [k for k in (s.strip() for s in known if s) if len(k) >= g.MIN_KNOWN]
        self.counts = Counter()
        self._lines = self.pack.line_masker()
        self._json_keys = self.pack.json_secret_keys
        self._pem = None          # [prefix, label, lines] inside a PEM block
        self._ppk = 0             # PuTTY key lines still to swallow
        self._hexrun = 0
        self._hexlead = ''

    def feed(self, line, backstops=True):
        """One physical line in, zero or more lines out."""
        if self._pem is not None:
            return self._in_pem(line)
        if self._ppk:
            self._ppk -= 1
            return ['<masked:ppk-private-lines>'] if not self._ppk else []
        out = []
        m = g.PEM_BEGIN_RE.search(line)
        if m and f'-----END {m.group(1)}-----' not in line[m.end():]:
            out.extend(self._flush_hex())
            self._pem = [line[:m.start()], m.group(1), [line[m.start():]]]
            return out
        p = g.PPK_RE.match(line)
        if p and int(p.group(1)):
            self._ppk = int(p.group(1))
            self.counts['ppk'] += 1
            return self._flush_hex() + [line]
        if g.HEXLINE_RE.match(line) and re.search(r'[A-Fa-f]', line):
            if not self._hexrun:
                self._hexlead = line[:len(line) - len(line.lstrip())]
            self._hexrun += 1
            return out
        out.extend(self._flush_hex())
        line = self._lines.line(line, self.counts)
        line = g.mask_line(line, self.counts, self._json_keys, backstops)
        out.append(g.mask_known(line, self.known, self.counts))
        return out

    def _in_pem(self, line):
        prefix, label, body = self._pem
        body.append(line)
        end = f'-----END {label}-----'
        if end not in line:
            return []
        self._pem = None
        self.counts['pem'] += 1
        return [prefix + g.pem_marker(label, '\n'.join(body)) + line.split(end, 1)[1]]

    def _flush_hex(self):
        if not self._hexrun:
            return []
        n, self._hexrun = self._hexrun, 0
        self.counts['hexdump'] += 1
        return [f'{self._hexlead}<hexdump:{n} lines>']

    def close(self):
        out = self._flush_hex()
        if self._pem is not None:            # unterminated block: never let the body through
            prefix, label, _ = self._pem
            out.append(prefix + f'<masked:unterminated-{label.lower().replace(" ", "-")}>')
            self.counts['pem'] += 1
            self._pem = None
        if self._ppk:
            out.append('<masked:ppk-private-lines>')
            self._ppk = 0
        return out

    def text(self, raw, backstops=True):
        if not raw:
            return raw
        trailing = raw.endswith('\n')
        lines = raw.replace('\r\n', '\n').replace('\r', '\n').split('\n')
        out = []
        for line in lines[:-1] if trailing else lines:
            out.extend(self.feed(line, backstops))
        out.extend(self.close())
        return '\n'.join(out) + ('\n' if trailing else '')

    def leaks(self, text):
        """1-based line numbers where a known secret (or an encoding of it) still appears."""
        return [i for i, line in enumerate(text.split('\n'), 1)
                if any(v in line for k in self.known for v in g.variants(k))]

    def summary(self):
        return ', '.join(f'{k}={v}' for k, v in sorted(self.counts.items())) or 'nothing'


def mask_json(obj, masker):
    """A masked copy of a parsed JSON value: secret keys by name, every string by the rules."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower()
            if isinstance(v, str) and v and g.json_key_is_secret(kl, masker.pack.json_secret_keys):
                masker.counts['json-key'] += 1
                out[k] = g.MASK
            elif isinstance(v, str):
                out[k] = masker.text(v, backstops=kl not in g.IDENTITY_KEYS)
            else:
                out[k] = mask_json(v, masker)
        return out
    if isinstance(obj, list):
        return [mask_json(v, masker) for v in obj]
    if isinstance(obj, str):
        return masker.text(obj)
    return obj
