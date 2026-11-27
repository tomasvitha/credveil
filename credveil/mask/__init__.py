"""Masking of secrets in device and tool output before an LLM reads it.

Rules come in layers: multi-line blocks (PEM, PuTTY keys, hex dumps), the vendor pack
(credveil.packs), the vendor-neutral rules, then the known credentials. It is a denylist and
therefore best-effort: a secret it misses is a bug to fix with a test case, and so is a mask
that hides diagnostic content.
"""
from .engine import Masker, mask_json
from .generic import MASK, net_mask

__all__ = ['MASK', 'Masker', 'mask_json', 'net_mask', 'mask_any']


def mask_any(text, known=()):
    """Mask text of unknown origin: the full pack when a fingerprint names the system, else the net."""
    from .. import packs
    pack = packs.detect(text) if isinstance(text, str) else None
    if pack is None:
        return net_mask(text, known)
    return Masker(pack.name, known=known).text(text)
