"""Masking of secrets in device and tool output before an LLM reads it.

Rules come in layers: multi-line blocks (PEM, PuTTY keys, hex dumps), the vendor pack
(credveil.packs), the vendor-neutral rules, then the known credentials. It is a denylist and
therefore best-effort: a secret it misses is a bug to fix with a test case, and so is a mask
that hides diagnostic content.
"""
from .engine import Masker, mask_json
from .generic import MASK, net_mask

__all__ = ['MASK', 'Masker', 'mask_json', 'net_mask', 'mask_any', 'mask_statement']


def mask_any(text, known=()):
    """Mask text of unknown origin: the full pack when a fingerprint names the system, else the net."""
    from .. import packs
    pack = packs.detect(text) if isinstance(text, str) else None
    if pack is None:
        return net_mask(text, known)
    return Masker(pack.name, known=known).text(text)


def mask_statement(vendor, stmt, context=''):
    """One config statement on its own, for tools that flatten configs.

    context is the line that sets the statement's scope (a RouterOS `/menu`, a FortiOS
    `config …`); it is fed first and not returned.
    """
    m = Masker(vendor)
    if context:
        m.feed(context)
    return m.text(stmt)
