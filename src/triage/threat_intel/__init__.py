"""Threat Intel delegated agent — IOC enrichment mini-loop (RFC-0002 / US-0005).

A self-contained package that enriches external IOCs (public IPs, domains,
hashes) via a dedicated mini-loop with its own LLM prompt, its own read-only
TI tools, and its own journal tagging (``agent="threat-intel"``).

Public surface for group-A consumers (tests, group-B executor integration):

* ``TIReport``        — the validated enrichment result (``models.py``)
* ``IOCType``         — the three external-IOC classes (``models.py``)
* ``classify_ioc``    — deterministic external-IOC classifier (``classifier.py``)
* ``enrich``          — the mini-loop entry point (``loop.py``)
* ``TIToolRegistry``  — the three read-only TI tools (``tools.py``)
* ``TIFixtureDataSource`` — fixture-backed data source (``tools.py``)
"""

from triage.threat_intel.classifier import IOCType, classify_ioc
from triage.threat_intel.loop import enrich
from triage.threat_intel.models import SourceFinding, TIReport
from triage.threat_intel.tools import TIFixtureDataSource, TIToolRegistry

__all__ = [
    "IOCType",
    "SourceFinding",
    "TIFixtureDataSource",
    "TIReport",
    "TIToolRegistry",
    "classify_ioc",
    "enrich",
]
