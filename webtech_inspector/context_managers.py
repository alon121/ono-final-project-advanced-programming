class AnalysisSession:
    def __init__(self, target):
        self.target = target
        self.previous_status = None

    def __enter__(self):
        if self.target.status == "processing":
            raise RuntimeError(f"Target {self.target.target_id} is already being processed")
        self.previous_status = self.target.status
        self.target.status = "processing"
        return self.target

    def __exit__(self, error_type, error, traceback):
        # always put the old status back, even when there was an error inside the with block
        self.target.status = self.previous_status
        # False means: do not hide the error, let it continue to the caller
        return False
