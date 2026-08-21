"""Circuit breaker — Python port of oc-fwd src/proxy/circuit.ts."""
import time


class Circuit:
    def __init__(self, threshold: int, cooldown_ms: int, now=None):
        self.threshold = threshold
        self.cooldown_ms = cooldown_ms
        self._now = now or (lambda: int(time.time() * 1000))
        self.failures = 0
        self.opened_at = 0

    def allow(self) -> bool:
        if self.threshold <= 0:
            return True
        if self.failures >= self.threshold:
            if self._now() - self.opened_at >= self.cooldown_ms:
                self.failures = 0
                return True
            return False
        return True

    def record_failure(self):
        if self.threshold <= 0:
            return
        self.failures += 1
        if self.failures >= self.threshold:
            self.opened_at = self._now()

    def record_success(self):
        self.failures = 0

    def reset(self):
        self.failures = 0
        self.opened_at = 0
