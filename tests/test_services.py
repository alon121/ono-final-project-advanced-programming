from webtech_inspector.services import filter_cves_by_min_severity, sort_cves_by_severity

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


def make_vuln(cve_id, severity):
    return {"cve_id": cve_id, "summary": "", "severity": severity}


def ids(vulns):
    return [vuln["cve_id"] for vuln in vulns]


def test_sort_most_severe_first():
    vulns = [make_vuln("A", 3), make_vuln("B", 1), make_vuln("C", 4), make_vuln("D", 2)]
    assert ids(sort_cves_by_severity(vulns)) == ["B", "D", "A", "C"]


def test_sort_unknown_severity_last():
    vulns = [make_vuln("A", None), make_vuln("B", 4), make_vuln("C", 1)]
    assert ids(sort_cves_by_severity(vulns)) == ["C", "B", "A"]


def test_sort_same_severity_keeps_order():
    vulns = [make_vuln("A", 2), make_vuln("B", 2), make_vuln("C", 2)]
    assert ids(sort_cves_by_severity(vulns)) == ["A", "B", "C"]


def test_sort_does_not_change_the_original_list():
    vulns = [make_vuln("A", 3), make_vuln("B", 1)]
    sort_cves_by_severity(vulns)
    assert ids(vulns) == ["A", "B"]


def test_sort_empty_list():
    assert sort_cves_by_severity([]) == []
