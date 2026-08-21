from threat_alerting.domain.signals import extract_categories, extract_cves


def test_cve_extraction_normalizes_and_deduplicates_in_first_seen_order() -> None:
    text = (
        "cve-2026-1234 and CVE-2025-1234567 are relevant. "
        "CVE-2026-1234 is repeated; CVE-2026-123 and CVE-2026-12345678 are invalid."
    )

    assert extract_cves(text) == ("CVE-2026-1234", "CVE-2025-1234567")


def test_category_extraction_does_not_tag_negated_active_exploitation() -> None:
    categories = extract_categories(
        "CVE-2026-1234 allows remote code execution but is not actively exploited."
    )

    assert "rce" in categories
    assert "active_exploitation" not in categories
