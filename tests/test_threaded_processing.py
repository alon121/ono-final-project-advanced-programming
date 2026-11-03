import threading

from webtech_inspector.models import ScanTarget
from webtech_inspector.threaded_processing import (ActiveSessionRegistry, SafeThreadedSessionRunner,
                                                   TargetAlreadyProcessingError)


def run_in_two_threads(runner, first_target, second_target):
    successes = []
    errors = []
    # the barrier makes both threads start at the same moment
    start_together = threading.Barrier(2)

    def work(target):
        start_together.wait()
        try:
            successes.append(runner.run_session(target))
        except TargetAlreadyProcessingError as error:
            errors.append(error)

    threads = [threading.Thread(target=work, args=(first_target,)),
               threading.Thread(target=work, args=(second_target,))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return successes, errors


def test_threaded_session_collision_prevented():
    runner = SafeThreadedSessionRunner(ActiveSessionRegistry())
    target = ScanTarget("site-1", "https://a.example.test")

    successes, errors = run_in_two_threads(runner, target, target)

    assert len(successes) == 1
    assert len(errors) == 1
    assert target.status == "idle"


def test_threaded_session_distinct_targets_allowed():
    runner = SafeThreadedSessionRunner(ActiveSessionRegistry())
    first = ScanTarget("site-1", "https://a.example.test")
    second = ScanTarget("site-2", "https://b.example.test")

    successes, errors = run_in_two_threads(runner, first, second)

    assert len(successes) == 2
    assert errors == []


def test_target_is_released_after_session():
    registry = ActiveSessionRegistry()
    runner = SafeThreadedSessionRunner(registry)
    target = ScanTarget("site-1", "https://a.example.test")

    runner.run_session(target)
    # the same target can run again once the first session ended
    assert runner.run_session(target) == "Target site-1 processed successfully"
    assert registry._active_targets == set()
