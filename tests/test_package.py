"""Baseline package test — keeps the 100% coverage gate green from day zero."""

import triage


def test_package_exposes_version() -> None:
    assert triage.__version__ == "0.1.0"
