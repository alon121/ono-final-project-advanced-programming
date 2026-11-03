from webtech_inspector.services import filter_cves_by_min_severity

VULNS = [
    {"cve_id": "CVE-1", "summary": "", "severity": 1},
    {"cve_id": "CVE-2", "summary": "", "severity": 2},
    {"cve_id": "CVE-3", "summary": "", "severity": 3},
    {"cve_id": "CVE-4", "summary": "", "severity": None},
]


def test_filter_keeps_only_severe_enough():
    # 1 is the most severe, so "at least 2" means 1 or 2
    result = filter_cves_by_min_severity(VULNS, 2)
    assert [vuln["cve_id"] for vuln in result] == ["CVE-1", "CVE-2"]


def test_filter_skips_unknown_severity():
    result = filter_cves_by_min_severity(VULNS, 4)
    assert "CVE-4" not in [vuln["cve_id"] for vuln in result]


def test_filter_empty_list():
    assert filter_cves_by_min_severity([], 2) == []
