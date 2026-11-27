"""Reusable tokenizers. A pack picks the ones that fit its system and fills them with data.

  KeywordRules     `keyword [type tokens] value` statements (Cisco-like CLIs), also `Keyword: value`
  AssignRules      `key=value` / `key: value` parameters (RouterOS, env vars, YAML, logs)
  TableMasker      column tables whose header names a secret column (`show crypto isakmp key`)
  RegexRule        one pack-specific form the tokenizers cannot express (positional values)
"""
import re
from dataclasses import dataclass, field

from .generic import MASK

_TOKEN_RE = re.compile(r'(\s+)|("(?:[^"\\]|\\.)*"\S*|\S+)')


def _masked(tok):
    return MASK in tok


def _mask_token(tok):
    return MASK + (';' if tok.endswith(';') else '')


@dataclass(frozen=True)
class KeywordRules:
    secret_words: frozenset
    type_tokens: frozenset = frozenset()              # say how the value is encoded, not the value
    not_after: dict = field(default_factory=dict)     # word -> next tokens that make it a non-secret use
    needs_next: dict = field(default_factory=dict)    # word -> it counts only before one of these
    skip_prefixes: tuple = ()                         # lines starting so carry free text (description)

    def mask(self, line, counts):
        stripped = line.lstrip()
        if not stripped or stripped.split(None, 1)[0].lower() in self.skip_prefixes:
            return line
        parts = [m.group(0) for m in _TOKEN_RE.finditer(line)]
        words = [i for i, p in enumerate(parts) if not p.isspace()]
        hit = False
        for n, i in enumerate(words):
            tok = parts[i]
            key, eq, val = tok.partition('=')
            if (eq and val and key.lower() in self.secret_words and not _masked(val)
                    and not (val.isdigit() and len(val) <= 3)):       # `key=16` is a key length
                parts[i] = f'{key}={_mask_token(val)}'
                hit = True
                continue
            w = tok.lower().rstrip(':')
            if w not in self.secret_words:
                continue
            j = self._value_index(w, [parts[k] for k in words], n)
            if j is not None:
                parts[words[j]] = _mask_token(parts[words[j]])
                hit = True
        if hit:
            counts['word'] += 1
        return ''.join(parts)

    def _value_index(self, word, toks, n):
        """Index in toks of the value that `word` at toks[n] introduces, or None."""
        j = n + 1
        if j >= len(toks) or toks[j].lower() in self.not_after.get(word, ()):
            return None
        if word in self.needs_next and toks[j].lower() not in self.needs_next[word]:
            return None
        while j < len(toks) - 1 and (toks[j].lower() in self.type_tokens or _is_label(toks[j])):
            j += 1
        cand = toks[j].lower().rstrip(':')
        if _masked(toks[j]) or cand in self.secret_words:
            return None                     # already done, or a nested keyword that takes over
        if cand.isdigit() and len(cand) <= 3 and any(t.lower().rstrip(':') in self.secret_words
                                                      for t in toks[j + 1:]):
            return None                     # a key id (`message-digest-key 1 md5 …`), value comes later
        return j


def _is_label(tok):
    return tok.endswith(':') and len(tok) > 1 and not tok[:-1].isdigit()


@dataclass(frozen=True)
class AssignRules:
    keys: frozenset
    suffixes: tuple = ()
    contains: tuple = ()          # substrings of a key name (env vars: DB_PASSWORD, AWS_SECRET_…)
    not_secret: frozenset = frozenset()
    separators: str = '='         # '=' or '=:'

    def __post_init__(self):
        sep = '|'.join(re.escape(c) for c in self.separators)
        object.__setattr__(self, '_rx', re.compile(
            r'(?<![\w.-])(?P<k>[A-Za-z_][\w.-]*)(?P<s>\s*(?:' + sep + r')\s*)'
            r'(?P<v>"(?:[^"\\]|\\.)*"|\'[^\']*\'|[^\s,;]+)'))

    def is_secret(self, key):
        k = key.lower()
        if k in self.not_secret:
            return False
        return (k in self.keys or k.endswith(self.suffixes)
                or any(c in k for c in self.contains))

    def mask(self, line, counts, extra=None):
        """extra(key) -> bool adds context-dependent keys (RouterOS `/snmp community name=`)."""
        n = 0

        def repl(m):
            nonlocal n
            k, v = m.group('k'), m.group('v')
            if _masked(v) or not (self.is_secret(k) or (extra and extra(k))):
                return m.group(0)
            n += 1
            return f'{k}{m.group("s")}{MASK}'
        new = self._rx.sub(repl, line)
        if n:
            counts['kv'] += n
        return new


@dataclass(frozen=True)
class RegexRule:
    """Mask group `group` of `pattern` wherever it matches."""
    pattern: re.Pattern
    group: int = 1
    category: str = 'rule'

    def mask(self, line, counts):
        def repl(m):
            s, e = m.span(self.group)
            whole = m.group(0)
            off = m.start()
            return whole[:s - off] + MASK + whole[e - off:]
        new, n = self.pattern.subn(repl, line)
        if n and new != line:
            counts[self.category] += n
        return new


class TableMasker:
    """Masks one column of a whitespace-aligned table whose header names a secret column.

    A header is a line with 2+ columns split by 2+ spaces where one column title matches
    `secret_columns`. Rows follow until a blank line; the cell under that title is masked.
    """
    _COL_RE = re.compile(r'\S+(?: \S+)*')

    def __init__(self, secret_columns):
        self.secret_columns = tuple(c.lower() for c in secret_columns)
        self._col = None          # (start, end) of the secret column in the current table

    def mask(self, line, counts):
        if not line.strip():
            self._col = None
            return line
        cols = [(m.start(), m.end(), m.group(0).lower()) for m in self._COL_RE.finditer(line)]
        if len(cols) >= 2:
            for k, (s, _, title) in enumerate(cols):
                if title in self.secret_columns:
                    end = cols[k + 1][0] if k + 1 < len(cols) else None
                    self._col = (s, end)
                    return line
        if self._col is None:
            return line
        s, end = self._col
        for cs, ce, _ in cols:
            if ce > s and (end is None or cs < end):
                counts['table'] += 1
                return line[:cs] + MASK + line[ce:]
        return line
