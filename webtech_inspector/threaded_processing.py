import threading
import time

from webtech_inspector.context_managers import AnalysisSession


class TargetAlreadyProcessingError(RuntimeError):
    pass


class ActiveSessionRegistry:
    def __init__(self):
        self._active_targets = set()
        self._lock = threading.Lock()

    def acquire_target(self, target_id):
        # the check and the add happen together under the lock,
        # so two threads cannot both see "free" and both start (check-then-act race)
        with self._lock:
            if target_id in self._active_targets:
                raise TargetAlreadyProcessingError(f"Target {target_id} is already being processed")
            self._active_targets.add(target_id)

    def release_target(self, target_id):
        with self._lock:
            self._active_targets.discard(target_id)


class SafeThreadedSessionRunner:
    def __init__(self, registry):
        self.registry = registry

    def run_session(self, target):
        self.registry.acquire_target(target.target_id)
        try:
            with AnalysisSession(target):
                time.sleep(0.1)
                return f"Target {target.target_id} processed successfully"
        finally:
            # always free the target, even if the analysis failed
            self.registry.release_target(target.target_id)
