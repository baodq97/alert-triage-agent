"""Deterministic external-IOC classifier (RFC-0002 §Decision).

``classify_ioc`` is the **security boundary** that keeps delegation out of LLM
reach: only values that pass this deterministic check trigger the TI mini-loop.
Internal or org-scoped identifiers always return ``None`` and never delegate.

Classification algorithm (applied in order — first match wins):

0. **Org-domain allowlist** (``TI_ORG_DOMAINS`` env var, comma-separated, empty
   by default) — if ``entity_value`` equals or is a subdomain of any listed org
   domain, classify ``None`` (internal, never delegated).  Empty env var = current
   behavior (no allowlist).  Example: ``TI_ORG_DOMAINS=corp.example.com,acme.io``
   means ``corp.example.com``, ``api.corp.example.com``, and ``*.acme.io`` all
   return ``None`` without reaching step 1.

1. **Public IP** — try to parse ``entity_value`` with ``ipaddress``; if it
   parses and is NOT in any private/reserved/loopback/link-local/multicast range
   as defined by ``ipaddress.ip_address.is_global``, classify ``"public_ip"``.
   Non-parseable strings fall through to step 2.

2. **Hash** — hex string whose length is exactly 32 (MD5), 40 (SHA-1), or 64
   (SHA-256) characters and contains only hex digits (case-insensitive).
   This step is intentionally before the domain check: a 32-char all-hex string
   that looks like a domain label (impossible in practice, but defensive) would
   wrongly classify as a domain otherwise.

3. **Domain** — heuristic FQDN check:
   * Contains at least one dot (at least two labels).
   * No empty labels (no ``..`` sequences).
   * TLD (last label) is two or more ASCII alpha characters (ICANN minimum).
   * Every label contains only ``[A-Za-z0-9-]`` and does not start/end with
     a hyphen (RFC 1123 relaxed — enough for the security boundary).
   Documented limits: single-label internal hostnames, purely numeric labels,
   underscore-containing labels, and IDN labels are all classified ``None``.

4. **None** — internal hostname, username, ARN, private IP, or any other
   org-scoped identifier.

The ``entity_type`` parameter is accepted for interface consistency (the executor
will pass it) but is NOT used in classification logic — classification is driven
entirely by the value's shape.  This prevents an attacker-controlled ``entity_type``
label from steering delegation.
"""

from __future__ import annotations

import ipaddress
import os
import re

from triage.threat_intel.models import IOCType

# Hash lengths: MD5=32, SHA-1=40, SHA-256=64.
_HASH_LENGTHS = frozenset({32, 40, 64})
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Domain label: starts and ends with alphanumeric; may contain hyphens in between.
_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$|^[a-zA-Z0-9]$")
# TLD must be two or more ASCII alpha characters (ICANN minimum).
_TLD_RE = re.compile(r"^[a-zA-Z]{2,}$")

_ENV_ORG_DOMAINS = "TI_ORG_DOMAINS"

__all__ = ["IOCType", "classify_ioc"]


def _org_domains() -> frozenset[str]:
    """Return the set of configured org domains from ``TI_ORG_DOMAINS``.

    Parses ``TI_ORG_DOMAINS`` (comma-separated, case-insensitive, leading/
    trailing whitespace stripped).  An unset or empty env var returns the empty
    frozenset, preserving existing behavior (no allowlist).
    """
    raw = os.environ.get(_ENV_ORG_DOMAINS, "")
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def _is_org_domain(value: str, org_domains: frozenset[str]) -> bool:
    """Return ``True`` when ``value`` equals or is a subdomain of an org domain.

    Comparison is case-insensitive.  ``value`` is a subdomain of ``org_domain``
    when it ends with ``"." + org_domain`` (the dot prevents a partial label
    match like ``evilcorp.example.com`` matching ``corp.example.com``).
    """
    if not org_domains:
        return False
    normalized = value.lower()
    for org_domain in org_domains:
        if normalized == org_domain or normalized.endswith("." + org_domain):
            return True
    return False


def classify_ioc(entity_type: str, entity_value: str) -> str | None:  # noqa: ARG001 — entity_type intentionally unused (see module docstring).
    """Classify ``entity_value`` as an external IOC type or return ``None``.

    Args:
        entity_type: The caller's label for this entity (e.g. ``"ip"``,
            ``"domain"``, ``"hash"``).  Accepted but **not used** — classification
            is driven only by the value's shape to prevent injection-steered
            delegation (RFC-0002 §Alternatives).
        entity_value: The raw entity value to classify.

    Returns:
        ``"public_ip"`` | ``"domain"`` | ``"hash"`` when the value is an
        external IOC; ``None`` for internal/org-scoped identifiers.
    """
    if not entity_value:
        return None

    # Step 0: Org-domain allowlist — configured internal domains are never delegated.
    if _is_org_domain(entity_value, _org_domains()):
        return None

    # Step 1: IP address (public only).
    try:
        addr = ipaddress.ip_address(entity_value)
    except ValueError:
        pass
    else:
        # ``is_global`` returns False for private, loopback, link-local,
        # reserved, and documentation addresses (Python ≥3.11), but returns
        # True for multicast (224.0.0.0/4) — exclude multicast explicitly since
        # multicast addresses are never external IOCs used in threat intelligence.
        if addr.is_global and not addr.is_multicast:
            return "public_ip"
        return None

    # Step 2: Hash — checked before domain to avoid false domain match.
    if len(entity_value) in _HASH_LENGTHS and _HEX_RE.match(entity_value):
        return "hash"

    # Step 3: Domain FQDN heuristic.
    if _looks_like_fqdn(entity_value):
        return "domain"

    return None


def _looks_like_fqdn(value: str) -> bool:
    """Return True when ``value`` has the shape of a plausible FQDN.

    Heuristic limits (documented in module docstring):
    - Single-label hostnames (no dot): rejected.
    - Empty labels (``..``): rejected.
    - Numeric TLD (e.g. the last octet of an IP-like string): rejected.
    - Single-character TLD: rejected (ICANN minimum is 2 alpha).
    - Underscore labels, IDN labels: rejected (not in the valid-label regex).
    """
    if "." not in value:
        return False
    labels = value.split(".")
    if any(label == "" for label in labels):
        return False
    tld = labels[-1]
    if not _TLD_RE.match(tld):
        return False
    return all(_LABEL_RE.match(label) for label in labels[:-1])
