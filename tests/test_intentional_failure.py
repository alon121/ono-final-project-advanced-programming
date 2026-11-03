from webtech_inspector.services import SeverityFirstStrategy


def test_critical_score_on_purpose_wrong():
    # this test fails ON PURPOSE, to show what a failing test looks like.
    # a critical vulnerability (severity 1) is worth 100 points, not 50.
    score = SeverityFirstStrategy().calculate_score(1, "content")
    assert score == 50.0
