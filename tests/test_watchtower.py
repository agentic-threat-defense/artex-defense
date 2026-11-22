"""Offline unit tests for the scheduled defensive threat-intelligence Watchtower."""

from pathlib import Path
from unittest.mock import patch

import pytest

from artex_defense.watchtower import (
    DEFAULT_FEEDS,
    parse_feed_xml,
    run_watchtower,
    validate_feed_url,
)

SAMPLE_RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Defensive Security Blog</title>
    <item>
      <title>New AntiFox &amp; ARTEX Fork Targeting Okta MFA Fatigue</title>
      <link>https://unit42.paloaltonetworks.com/artex-antifox-okta-2026/</link>
      <pubDate>Sat, 21 Nov 2026 12:00:00 GMT</pubDate>
      <description>&lt;p&gt;Operators deployed AntiFox from 203.0.113.77 against Okta workflows.&lt;/p&gt;</description>
    </item>
    <item>
      <title>Quarterly Cloud Storage Pricing Update</title>
      <link>https://unit42.paloaltonetworks.com/storage-pricing/</link>
      <pubDate>Sat, 21 Nov 2026 11:00:00 GMT</pubDate>
      <description>Routine pricing update unrelated to security threats.</description>
    </item>
  </channel>
</rss>
"""

SAMPLE_ATOM = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <title>Recent Commits to artex-detections:main</title>
  <entry>
    <title>Add Sigma rule for Strix agent and MadPot API key harvesting</title>
    <link href="https://github.com/ThreatDefence/artex-detections/commit/abc1234"/>
    <updated>2026-11-21T12:30:00Z</updated>
    <content>Added detection for OPENAI_API_KEY scraping by autonomous pentest frameworks.</content>
  </entry>
</feed>
"""


def test_validate_feed_url_enforces_https_and_strict_allowlist() -> None:
    validate_feed_url("https://unit42.paloaltonetworks.com/feed/")
    validate_feed_url("https://github.com/ThreatDefence/agentic-attack-detections/commits/main.atom")
    validate_feed_url("https://www.ic3.gov/CSA/RSS")
    validate_feed_url("https://www.rapid7.com/blog/rss/")
    validate_feed_url("https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/")
    validate_feed_url("https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml")
    validate_feed_url("https://cert.europa.eu/publications/threat-intelligence-rss")
    validate_feed_url("https://blogs.jpcert.or.jp/en/atom.xml")
    validate_feed_url("https://www.cyber.gov.au/rss/alerts")
    validate_feed_url("https://www.boho.or.kr/kr/rss.do?bbsId=B0000133")
    validate_feed_url("https://andpalmier.com/index.xml")
    validate_feed_url("https://www.wiz.io/feed/rss.xml")
    validate_feed_url("https://sec.okta.com/rss.xml")
    validate_feed_url("https://www.greynoise.io/blog/rss.xml")
    validate_feed_url("https://isc.sans.edu/rssfeed.xml")
    validate_feed_url("https://research.checkpoint.com/feed/")
    validate_feed_url("https://socradar.io/feed/")
    validate_feed_url("https://blog.ostorlab.co/feed/rss.xml")
    validate_feed_url("https://cloudsecurityalliance.org/feed/")
    validate_feed_url("https://threatdefence.com/feed")
    validate_feed_url("https://threatdefence.com/security-advisories/feed")
    validate_feed_url("https://github.com/kh20134/artex-defense-kit/commits/main.atom")
    validate_feed_url("https://github.com/Kshot3000/artex-defense-kit/commits/main.atom")
    validate_feed_url("https://feeds.feedburner.com/TheHackersNews")
    validate_feed_url("https://www.malware-traffic-analysis.net/blog-entries.rss")
    validate_feed_url("https://suricata.io/feed/")
    for spec in DEFAULT_FEEDS:
        validate_feed_url(spec.url)

    with pytest.raises(ValueError, match="HTTPS"):
        validate_feed_url("http://unit42.paloaltonetworks.com/feed/")
    with pytest.raises(ValueError, match="raw IP"):
        validate_feed_url("https://38.244.50.120:8000/")
    with pytest.raises(ValueError, match="non-allowlisted"):
        validate_feed_url("https://untrusted-attacker.example/feed.xml")


def test_parse_rss_and_atom_feeds() -> None:
    rss_items = parse_feed_xml(SAMPLE_RSS, source="Unit 42")
    assert len(rss_items) == 2
    assert "AntiFox" in rss_items[0].title
    assert "<p>" not in rss_items[0].summary

    atom_items = parse_feed_xml(SAMPLE_ATOM, source="ThreatDefence", always_relevant=True)
    assert len(atom_items) == 1
    assert atom_items[0].link == "https://github.com/ThreatDefence/artex-detections/commit/abc1234"


def test_watchtower_dedup_defanging_and_optional_local_llm_gap_analysis(tmp_path: Path) -> None:
    rss_path = tmp_path / "unit42.xml"
    atom_path = tmp_path / "td_commits.xml"
    rss_path.write_text(SAMPLE_RSS, encoding="utf-8")
    atom_path.write_text(SAMPLE_ATOM, encoding="utf-8")
    state_dir = tmp_path / "wt_state"

    with patch("artex_defense.watchtower.GemmaWorker.delegate", return_value="## Gap Summary\n- Covered by llm_api_key_harvesting") as mock_llm:
        first = run_watchtower(
            state_dir=state_dir,
            rules_dir=Path("rules/sigma"),
            offline_feed_files=[rss_path, atom_path],
            with_gemma4=True,
        )
        assert first["total_fetched"] == 3
        assert first["new_relevant_count"] == 2
        assert first["new_ignored"] == 1
        assert first["already_seen"] == 0
        assert first["llm_gap_analysis_ran"] is True
        assert first["digest_path"] is not None
        mock_llm.assert_called_once()

        digest_text = Path(first["digest_path"]).read_text(encoding="utf-8")
        assert "hxxps://" in digest_text
        assert "203.0.113.77" not in digest_text  # pseudonymized/sanitized
        assert "Gap Summary" in digest_text

        # Second run with identical feeds must skip everything and NOT invoke the GPU/LLM!
        second = run_watchtower(
            state_dir=state_dir,
            rules_dir=Path("rules/sigma"),
            offline_feed_files=[rss_path, atom_path],
            with_gemma4=True,
        )
        assert second["already_seen"] == 3
        assert second["new_relevant_count"] == 0
        assert second["llm_gap_analysis_ran"] is False
        assert second["digest_path"] is None
        assert mock_llm.call_count == 1


def test_parse_release_atom_category_preserved() -> None:
    rel_items = parse_feed_xml(SAMPLE_ATOM, source="SigmaHQ/sigma [Releases]", always_relevant=True, category="release")
    assert len(rel_items) == 1
    assert rel_items[0].category == "release"
    assert rel_items[0].always_relevant is True


def test_watchtower_highlights_agentic_pcap_drops_without_non_agentic_spam(tmp_path: Path) -> None:
    mta_rss = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Malware-Traffic-Analysis</title>
    <item>
      <title>2026-11-23 - ARTEX / BLOODALCHEMY traffic capture (.pcap) and Suricata alerts</title>
      <link>https://www.malware-traffic-analysis.net/2026/11/23/index.html</link>
      <pubDate>Mon, 23 Nov 2026 10:00:00 GMT</pubDate>
      <description>Sanitized packet capture (.pcapng) of autonomous pentest framework hitting edge gateway.</description>
    </item>
    <item>
      <title>2026-11-22 - Commodity infostealer traffic capture (.pcap)</title>
      <link>https://www.malware-traffic-analysis.net/2026/11/22/index.html</link>
      <pubDate>Sun, 22 Nov 2026 10:00:00 GMT</pubDate>
      <description>Routine commodity infostealer traffic capture from phishing email.</description>
    </item>
  </channel>
</rss>
"""
    feed_file = tmp_path / "mta.xml"
    feed_file.write_text(mta_rss, encoding="utf-8")
    res = run_watchtower(
        state_dir=tmp_path / "wt_pcap",
        rules_dir=Path("rules/sigma"),
        offline_feed_files=[feed_file],
        with_gemma4=False,
    )
    assert res["new_relevant_count"] == 1
    assert res["new_pcap_drops_count"] == 1
    assert res["new_ignored"] == 1
    digest = Path(res["digest_path"]).read_text(encoding="utf-8")
    assert "## PCAP & Network-Capture Drops (High Priority)" in digest
    assert "BLOODALCHEMY" in digest
    assert "Commodity infostealer" not in digest
