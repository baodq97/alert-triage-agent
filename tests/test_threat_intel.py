"""Tests for the threat_intel package — group A (self-contained, no executor).

Coverage targets:
* models.py          — TIReport strict/lax contract, SourceFinding, IOCType
* classifier.py      — classify_ioc exhaustive boundary tests
* tools.py           — TIFixtureDataSource fixture hits/misses, TIToolRegistry specs
* loop.py            — enrich() with FakeLLM; partial/failure degradation paths

All tests use FakeLLM + NoopJournal — no live LLM, no network.
"""

from __future__ import annotations

import importlib.resources
import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

import pytest
from pydantic import ValidationError

import triage.threat_intel as _ti_pkg
from triage.errors import ToolError
from triage.journal import NoopJournal
from triage.llm import Completion, FakeLLM
from triage.threat_intel.classifier import IOCType, classify_ioc
from triage.threat_intel.loop import enrich
from triage.threat_intel.models import SourceFinding, TIReport
from triage.threat_intel.tools import TIFixtureDataSource, TIToolRegistry

# ---------------------------------------------------------------------------
# models.py — TIReport contract
# ---------------------------------------------------------------------------


class TestTIReport:
    def _valid_source_finding(self) -> dict[str, Any]:
        return {
            "source": "multi_source_reputation",
            "summary": "Known Tor exit node, score 95.",
            "citation": "fixture:reputation/185.220.101.5",
        }

    def test_valid_report_roundtrip(self) -> None:
        data = {
            "ioc_type": "public_ip",
            "ioc_value": "185.220.101.5",
            "source_findings": [self._valid_source_finding()],
            "overall_assessment": "Confirmed malicious Tor exit node.",
            "confidence": 0.95,
        }
        report = TIReport.model_validate(data)
        assert report.ioc_type == "public_ip"
        assert report.ioc_value == "185.220.101.5"
        assert len(report.source_findings) == 1
        assert report.confidence == 0.95

    def test_report_extra_fields_ignored(self) -> None:
        """LLM-output lax model: extra keys are silently dropped."""
        data = {
            "ioc_type": "domain",
            "ioc_value": "evil.example.com",
            "source_findings": [],
            "overall_assessment": "Suspicious domain.",
            "confidence": 0.5,
            "hallucinated_key": "should be dropped",
        }
        report = TIReport.model_validate(data)
        assert not hasattr(report, "hallucinated_key")

    def test_report_confidence_out_of_range_rejects(self) -> None:
        with pytest.raises(ValidationError):
            TIReport.model_validate(
                {
                    "ioc_type": "hash",
                    "ioc_value": "a" * 32,
                    "source_findings": [],
                    "overall_assessment": "x",
                    "confidence": 1.5,  # out of [0, 1]
                }
            )

    def test_report_missing_required_field_rejects(self) -> None:
        with pytest.raises(ValidationError):
            TIReport.model_validate(
                {
                    "ioc_type": "public_ip",
                    # ioc_value missing
                    "source_findings": [],
                    "overall_assessment": "x",
                    "confidence": 0.5,
                }
            )

    def test_source_finding_lax(self) -> None:
        """SourceFinding tolerates extra keys from LLM."""
        sf = SourceFinding.model_validate(
            {
                "source": "passive_dns",
                "summary": "Resolves to known-bad.",
                "citation": "fixture:passive_dns/evil.example.com",
                "extra": "ignored",
            }
        )
        assert sf.source == "passive_dns"

    def test_source_finding_missing_source_rejects(self) -> None:
        with pytest.raises(ValidationError):
            SourceFinding.model_validate({"summary": "x", "citation": "y"})

    def test_ioc_type_values(self) -> None:
        assert set(IOCType.__args__) == {"public_ip", "domain", "hash"}  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# classifier.py — exhaustive boundary tests
# ---------------------------------------------------------------------------


class TestClassifyPublicIP:
    def test_known_bad_public_ip(self) -> None:
        assert classify_ioc("ip", "185.220.101.5") == "public_ip"

    def test_benign_public_ip(self) -> None:
        # 8.8.8.8 is Google Public DNS — a real globally-routable public IP.
        assert classify_ioc("ip", "8.8.8.8") == "public_ip"

    def test_documentation_range_rejected(self) -> None:
        # 203.0.113.22 is TEST-NET-3 (RFC 5737) — not globally routable.
        assert classify_ioc("ip", "203.0.113.22") is None

    def test_rfc1918_private_10(self) -> None:
        assert classify_ioc("ip", "10.0.0.1") is None

    def test_rfc1918_private_172(self) -> None:
        assert classify_ioc("ip", "172.16.0.1") is None

    def test_rfc1918_private_192_168(self) -> None:
        assert classify_ioc("ip", "192.168.1.100") is None

    def test_loopback_ipv4(self) -> None:
        assert classify_ioc("ip", "127.0.0.1") is None

    def test_loopback_ipv4_other(self) -> None:
        assert classify_ioc("ip", "127.255.255.255") is None

    def test_link_local_ipv4(self) -> None:
        assert classify_ioc("ip", "169.254.0.1") is None

    def test_multicast_ipv4(self) -> None:
        assert classify_ioc("ip", "224.0.0.1") is None

    def test_reserved_ipv4(self) -> None:
        # 100.64.0.0/10 — shared address space (RFC 6598)
        assert classify_ioc("ip", "100.64.0.1") is None

    def test_public_ipv6(self) -> None:
        assert classify_ioc("ip", "2001:db8::1") is None  # documentation range
        assert classify_ioc("ip", "2606:4700:4700::1111") == "public_ip"  # Cloudflare DNS

    def test_ipv6_loopback(self) -> None:
        assert classify_ioc("ip", "::1") is None

    def test_ipv6_link_local(self) -> None:
        assert classify_ioc("ip", "fe80::1") is None

    def test_invalid_ip_string(self) -> None:
        assert classify_ioc("ip", "not-an-ip") is None

    def test_entity_type_ignored_for_ip_value(self) -> None:
        """classify_ioc probes by value shape, not entity_type label."""
        # A valid public IP is recognized regardless of what entity_type says
        assert classify_ioc("host", "185.220.101.5") == "public_ip"


class TestClassifyDomain:
    def test_malicious_domain(self) -> None:
        assert classify_ioc("domain", "evil.example.com") == "domain"

    def test_simple_two_label_domain(self) -> None:
        assert classify_ioc("domain", "example.com") == "domain"

    def test_subdomain(self) -> None:
        assert classify_ioc("domain", "api.corp.example.io") == "domain"

    def test_short_tld_two_alpha(self) -> None:
        assert classify_ioc("domain", "google.uk") == "domain"

    def test_single_label_hostname_rejected(self) -> None:
        """No dot → internal hostname, not a domain."""
        assert classify_ioc("hostname", "webserver01") is None

    def test_numeric_tld_rejected(self) -> None:
        """A purely numeric TLD (e.g. from an IP) is not a domain."""
        assert classify_ioc("domain", "192.168.1") is None

    def test_tld_too_short_rejected(self) -> None:
        """Single-character TLD — too short to be real (ICANN ≥2)."""
        assert classify_ioc("domain", "host.x") is None

    def test_empty_label_rejected(self) -> None:
        assert classify_ioc("domain", "host..com") is None

    def test_ip_not_classified_as_domain(self) -> None:
        """IPs with dots should resolve as public_ip, not domain."""
        result = classify_ioc("ip", "8.8.8.8")
        assert result == "public_ip"

    def test_domain_with_hyphen(self) -> None:
        assert classify_ioc("domain", "my-corp.example.com") == "domain"

    def test_internal_hostname_with_tld_rejected(self) -> None:
        """Single-label host (no dot in value) is internal."""
        assert classify_ioc("hostname", "ldap") is None

    def test_invalid_non_tld_label_rejected(self) -> None:
        """A label before the TLD that fails _LABEL_RE (starts with hyphen)."""
        # "-bad" starts with a hyphen, which _LABEL_RE rejects.
        assert classify_ioc("domain", "-bad.example.com") is None


class TestClassifyHash:
    def test_md5(self) -> None:
        assert classify_ioc("hash", "d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_sha1(self) -> None:
        assert classify_ioc("hash", "da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"

    def test_sha256(self) -> None:
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert classify_ioc("hash", sha256) == "hash"

    def test_hash_uppercase(self) -> None:
        assert classify_ioc("hash", "D41D8CD98F00B204E9800998ECF8427E") == "hash"

    def test_hash_wrong_length(self) -> None:
        assert classify_ioc("hash", "d41d8cd98f00b204e980") is None

    def test_hash_non_hex(self) -> None:
        assert classify_ioc("hash", "g" * 32) is None


class TestClassifyInternalIdentifiers:
    def test_username(self) -> None:
        assert classify_ioc("user", "alice") is None

    def test_arn(self) -> None:
        assert classify_ioc("arn", "arn:aws:iam::123456789012:user/alice") is None

    def test_private_ip_as_entity(self) -> None:
        assert classify_ioc("ip", "10.200.3.47") is None

    def test_empty_value(self) -> None:
        assert classify_ioc("entity", "") is None


# ---------------------------------------------------------------------------
# tools.py — TIFixtureDataSource + TIToolRegistry
# ---------------------------------------------------------------------------


class TestTIFixtureDataSource:
    def setup_method(self) -> None:
        self.source = TIFixtureDataSource()

    def test_reputation_known_bad_ip(self) -> None:
        data = self.source.fetch("multi_source_reputation", {"ioc": "185.220.101.5"})
        assert data["known_bad"] is True
        assert data["score"] >= 80

    def test_reputation_benign_ip(self) -> None:
        data = self.source.fetch("multi_source_reputation", {"ioc": "8.8.8.8"})
        assert data["known_bad"] is False

    def test_passive_dns_malicious_domain(self) -> None:
        data = self.source.fetch("passive_dns", {"ioc": "evil.example.com"})
        assert "resolutions" in data or "records" in data or len(data) > 0

    def test_passive_dns_benign_domain(self) -> None:
        data = self.source.fetch("passive_dns", {"ioc": "google.com"})
        assert isinstance(data, dict)

    def test_threat_feed_known_bad_sha256(self) -> None:
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        data = self.source.fetch("threat_feed", {"ioc": sha256})
        assert "malware_family" in data or "tags" in data or isinstance(data, dict)

    def test_miss_raises_permanent_tool_error(self) -> None:
        with pytest.raises(ToolError) as exc_info:
            self.source.fetch("multi_source_reputation", {"ioc": "1.2.3.4"})
        assert not exc_info.value.transient

    def test_unknown_tool_raises_permanent_tool_error(self) -> None:
        with pytest.raises(ToolError) as exc_info:
            self.source.fetch("no_such_tool", {"ioc": "anything"})
        assert not exc_info.value.transient

    def test_missing_ioc_key_raises_tool_error(self) -> None:
        with pytest.raises(ToolError) as exc_info:
            self.source.fetch("multi_source_reputation", {})
        assert not exc_info.value.transient


class TestTIToolRegistry:
    def setup_method(self) -> None:
        self.registry = TIToolRegistry()

    def test_has_three_tools(self) -> None:
        assert len(self.registry.names()) == 3

    def test_tool_names(self) -> None:
        assert set(self.registry.names()) == {
            "multi_source_reputation",
            "passive_dns",
            "threat_feed",
        }

    def test_specs_structure(self) -> None:
        for spec in self.registry.specs():
            assert "name" in spec
            assert "description" in spec
            assert "args_schema" in spec

    def test_get_known_tool(self) -> None:
        tool = self.registry.get("multi_source_reputation")
        assert tool.name == "multi_source_reputation"

    def test_get_unknown_raises(self) -> None:
        with pytest.raises(KeyError):
            self.registry.get("lookup_user")


# ---------------------------------------------------------------------------
# loop.py — enrich() with FakeLLM
# ---------------------------------------------------------------------------


def _ti_report_json(
    ioc_type: str = "public_ip",
    ioc_value: str = "185.220.101.5",
    overall_assessment: str = "Confirmed malicious Tor exit node.",
    confidence: float = 0.95,
) -> str:
    report = {
        "ioc_type": ioc_type,
        "ioc_value": ioc_value,
        "source_findings": [
            {
                "source": "multi_source_reputation",
                "summary": "Score 95, tagged tor-exit-node.",
                "citation": "fixture:reputation/185.220.101.5",
            }
        ],
        "overall_assessment": overall_assessment,
        "confidence": confidence,
    }
    return json.dumps(report)


class TestEnrichSuccess:
    def test_returns_ti_report(self) -> None:
        llm = FakeLLM([_ti_report_json()])
        journal = NoopJournal()
        registry = TIToolRegistry()

        report = enrich("public_ip", "185.220.101.5", llm=llm, journal=journal, registry=registry)

        assert isinstance(report, TIReport)
        assert report.ioc_type == "public_ip"
        assert report.ioc_value == "185.220.101.5"
        assert report.confidence > 0

    def test_journal_emits_with_threat_intel_agent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """All journal events from enrich() must carry agent='threat-intel'."""
        emitted: list[dict[str, Any]] = []

        class CapturingJournal:
            def emit(
                self, event: str, payload: Mapping[str, Any], *, agent: str = "triage"
            ) -> None:
                emitted.append({"event": event, "agent": agent, **payload})

        llm = FakeLLM([_ti_report_json()])
        report = enrich(
            "public_ip",
            "185.220.101.5",
            llm=llm,
            journal=CapturingJournal(),  # type: ignore[arg-type]
            registry=TIToolRegistry(),
        )

        assert isinstance(report, TIReport)
        # Every emitted event carries agent="threat-intel"
        for ev in emitted:
            assert ev["agent"] == "threat-intel", f"event {ev['event']!r} has wrong agent"

    def test_tool_calls_journaled(self) -> None:
        """tool_called + tool_result events fire for each TI tool call."""
        emitted: list[str] = []

        class CapturingJournal:
            def emit(
                self, event: str, payload: Mapping[str, Any], *, agent: str = "triage"
            ) -> None:
                emitted.append(event)

        llm = FakeLLM([_ti_report_json()])
        enrich(
            "public_ip",
            "185.220.101.5",
            llm=llm,
            journal=CapturingJournal(),  # type: ignore[arg-type]
            registry=TIToolRegistry(),
        )

        assert "tool_called" in emitted
        assert "tool_result" in emitted
        assert "llm_call" in emitted

    def test_step_cap_three_respected(self) -> None:
        """The mini-loop calls at most 3 tools (one per TI tool) + 1 LLM call."""
        call_counts: dict[str, int] = {"tool_called": 0, "llm_call": 0}

        class CountingJournal:
            def emit(
                self, event: str, payload: Mapping[str, Any], *, agent: str = "triage"
            ) -> None:
                if event in call_counts:
                    call_counts[event] += 1

        llm = FakeLLM([_ti_report_json()])
        enrich(
            "public_ip",
            "185.220.101.5",
            llm=llm,
            journal=CountingJournal(),  # type: ignore[arg-type]
            registry=TIToolRegistry(),
        )

        assert call_counts["tool_called"] <= 3
        assert call_counts["llm_call"] == 1


class TestEnrichToolFailureDegrades:
    def test_all_tools_miss_produces_partial_report(self) -> None:
        """Unknown IOC → all tools miss → partial TIReport with low confidence."""
        # 1.2.3.4 has no TI fixture entry → all three tools return ok=False
        llm = FakeLLM(
            [
                json.dumps(
                    {
                        "ioc_type": "public_ip",
                        "ioc_value": "1.2.3.4",
                        "source_findings": [],
                        "overall_assessment": "No data found in any source.",
                        "confidence": 0.1,
                    }
                )
            ]
        )
        journal = NoopJournal()
        registry = TIToolRegistry()

        # 1.2.3.4 is not in TI fixtures → all tools miss → degraded synthesis
        report = enrich("public_ip", "1.2.3.4", llm=llm, journal=journal, registry=registry)

        assert isinstance(report, TIReport)
        assert report.ioc_value == "1.2.3.4"

    def test_llm_error_returns_none(self) -> None:
        """An LLM failure returns None (the caller maps this to ok=false Observation)."""
        # Two malformed replies: first triggers repair attempt, second exhausts it.
        llm = FakeLLM(["not-valid-json{{{", "still-not-valid{{{"])
        journal = NoopJournal()
        registry = TIToolRegistry()

        result = enrich("public_ip", "185.220.101.5", llm=llm, journal=journal, registry=registry)

        assert result is None

    def test_llm_error_emits_nothing_uncaught(self) -> None:
        """LLMError is swallowed by enrich; no exception propagates to the caller."""
        llm = FakeLLM(["bad{{{", "bad{{{"])
        journal = NoopJournal()

        # Must NOT raise
        result = enrich(
            "public_ip",
            "185.220.101.5",
            llm=llm,
            journal=journal,
            registry=TIToolRegistry(),
        )
        assert result is None


class TestEnrichLLMRepair:
    def test_repair_path_succeeds(self) -> None:
        """First raw reply malformed; repair reply valid → TIReport returned."""
        llm = FakeLLM(["bad-json{{{", _ti_report_json()])
        journal = NoopJournal()

        report = enrich(
            "public_ip",
            "185.220.101.5",
            llm=llm,
            journal=journal,
            registry=TIToolRegistry(),
        )

        assert isinstance(report, TIReport)

    def test_transport_retry_callback_emits_threat_intel_event(self) -> None:
        """The _ti_on_transport_retry closure emits llm_transport_retry agent='threat-intel'."""
        emitted: list[dict[str, Any]] = []

        class CapturingJournal:
            def emit(
                self, event: str, payload: Mapping[str, Any], *, agent: str = "triage"
            ) -> None:
                emitted.append({"event": event, "agent": agent, **payload})

        class RetryingFakeLLM:
            """Fires one transport retry callback then returns a valid TIReport."""

            model = "fake-model"

            def complete(
                self,
                messages: Any,
                response_model: type[Any],
                *,
                on_transport_retry: Any = None,
                on_repair: Any = None,
            ) -> Completion[Any]:
                if on_transport_retry is not None:
                    on_transport_retry("", 1, "simulated transport error")
                value = response_model.model_validate(json.loads(_ti_report_json()))
                return Completion(
                    value=value,
                    model="fake-model",
                    prompt_hash="abc123",
                    tokens=0,
                    latency_ms=0,
                )

        report = enrich(
            "public_ip",
            "185.220.101.5",
            llm=RetryingFakeLLM(),  # type: ignore[arg-type]
            journal=CapturingJournal(),  # type: ignore[arg-type]
            registry=TIToolRegistry(),
        )

        assert isinstance(report, TIReport)
        retry_events = [e for e in emitted if e["event"] == "llm_transport_retry"]
        assert len(retry_events) == 1
        assert retry_events[0]["agent"] == "threat-intel"


class TestEnrichHashIOC:
    def test_enrich_hash_ioc(self) -> None:
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        report_json = json.dumps(
            {
                "ioc_type": "hash",
                "ioc_value": sha256,
                "source_findings": [
                    {
                        "source": "threat_feed",
                        "summary": "Known malware dropper.",
                        "citation": f"fixture:threat_feed/{sha256}",
                    }
                ],
                "overall_assessment": "High-confidence malware.",
                "confidence": 0.9,
            }
        )
        llm = FakeLLM([report_json])
        report = enrich(sha256, sha256, llm=llm, journal=NoopJournal(), registry=TIToolRegistry())
        assert isinstance(report, TIReport)
        assert report.ioc_type == "hash"


class TestEnrichDomainIOC:
    def test_enrich_domain_ioc(self) -> None:
        report_json = json.dumps(
            {
                "ioc_type": "domain",
                "ioc_value": "evil.example.com",
                "source_findings": [
                    {
                        "source": "passive_dns",
                        "summary": "Resolves to known-bad IP.",
                        "citation": "fixture:passive_dns/evil.example.com",
                    }
                ],
                "overall_assessment": "Suspicious domain with bad resolutions.",
                "confidence": 0.75,
            }
        )
        llm = FakeLLM([report_json])
        report = enrich(
            "domain",
            "evil.example.com",
            llm=llm,
            journal=NoopJournal(),
            registry=TIToolRegistry(),
        )
        assert isinstance(report, TIReport)
        assert report.ioc_type == "domain"


# ---------------------------------------------------------------------------
# prompt file presence
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# classifier.py — org-domain allowlist knob (TI_ORG_DOMAINS, RFC-0003 §Parameters)
# ---------------------------------------------------------------------------


class TestOrgDomainAllowlist:
    def test_empty_env_unchanged_behavior(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Empty TI_ORG_DOMAINS (the default) leaves classification unchanged."""
        monkeypatch.delenv("TI_ORG_DOMAINS", raising=False)
        # A domain that would normally classify as "domain" still does.
        assert classify_ioc("domain", "evil.example.com") == "domain"

    def test_listed_domain_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A domain equal to a listed org domain classifies as None (internal)."""
        monkeypatch.setenv("TI_ORG_DOMAINS", "corp.example.com")
        assert classify_ioc("domain", "corp.example.com") is None

    def test_subdomain_of_listed_domain_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A subdomain of a listed org domain classifies as None (internal)."""
        monkeypatch.setenv("TI_ORG_DOMAINS", "corp.example.com")
        assert classify_ioc("domain", "api.corp.example.com") is None

    def test_deep_subdomain_of_listed_domain_returns_none(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A deeply nested subdomain of a listed org domain is also excluded."""
        monkeypatch.setenv("TI_ORG_DOMAINS", "acme.io")
        assert classify_ioc("domain", "a.b.c.acme.io") is None

    def test_unrelated_domain_still_classifies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A domain not in the allowlist still receives normal classification."""
        monkeypatch.setenv("TI_ORG_DOMAINS", "corp.example.com")
        assert classify_ioc("domain", "evil.example.com") == "domain"

    def test_partial_label_match_not_excluded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A domain whose suffix looks similar but is NOT a subdomain is not excluded.

        'evilcorp.example.com' must not be excluded by 'corp.example.com'
        because 'evilcorp.example.com' does not end with '.corp.example.com'.
        """
        monkeypatch.setenv("TI_ORG_DOMAINS", "corp.example.com")
        assert classify_ioc("domain", "evilcorp.example.com") == "domain"

    def test_multiple_org_domains_comma_separated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Multiple org domains are all applied."""
        monkeypatch.setenv("TI_ORG_DOMAINS", "corp.example.com,acme.io")
        assert classify_ioc("domain", "mail.corp.example.com") is None
        assert classify_ioc("domain", "acme.io") is None
        assert classify_ioc("domain", "evil.external.com") == "domain"

    def test_case_insensitive_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Org-domain comparison is case-insensitive."""
        monkeypatch.setenv("TI_ORG_DOMAINS", "Corp.Example.COM")
        assert classify_ioc("domain", "API.CORP.EXAMPLE.COM") is None

    def test_whitespace_trimmed_in_domain_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Leading/trailing whitespace around each entry is stripped."""
        monkeypatch.setenv("TI_ORG_DOMAINS", " corp.example.com , acme.io ")
        assert classify_ioc("domain", "corp.example.com") is None
        assert classify_ioc("domain", "acme.io") is None


class TestTIPromptFile:
    def test_prompt_file_exists(self) -> None:
        prompts_dir = (
            Path(importlib.resources.files(_ti_pkg).__str__()).parent.parent.parent  # type: ignore[arg-type]
            / "prompts"
        )
        prompt_path = prompts_dir / "threat_intel.md"
        assert prompt_path.exists(), f"prompts/threat_intel.md not found at {prompt_path}"

    def test_prompt_contains_sentinel(self) -> None:
        prompt_path = Path(__file__).parent.parent / "prompts" / "threat_intel.md"
        content = prompt_path.read_text(encoding="utf-8")
        assert "{{END_OF_STABLE}}" in content

    def test_prompt_contains_untrusted_block(self) -> None:
        prompt_path = Path(__file__).parent.parent / "prompts" / "threat_intel.md"
        content = prompt_path.read_text(encoding="utf-8")
        assert "<tool_results>" in content
