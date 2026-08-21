"""Anonymous -> API-key fallback — port of oc-fwd FallbackState."""
import random
import time

import os


class FallbackState:
    def __init__(self, fail_threshold: int, has_keys: bool,
                 probe_seconds: int = 3, hold_ms: int = 0):
        self.fail_threshold = fail_threshold
        self.has_keys = has_keys
        self.probe_seconds = probe_seconds
        self.hold_ms = hold_ms
        self.consec_anon_fail = {}  # model -> int
        self.keyed = set()          # models currently routed via key
        self.last_probe = {}        # model -> ts

    def should_fallback(self, model: str, status: int) -> bool:
        if not self.has_keys or not model:
            return False
        if status is not None and status != 429 and 200 <= status < 300:
            return False
        # Non-200 immediate fallback (400/5xx etc) — oc-fwd retry-and-fallback.md
        if status is not None and status != 429 and status >= 400:
            return True
        c = self.consec_anon_fail.get(model, 0) + 1
        self.consec_anon_fail[model] = c
        return c >= self.fail_threshold

    def note_success(self, model: str):
        self.consec_anon_fail.pop(model, None)

    def mark_keyed(self, model: str):
        if self.has_keys:
            self.keyed.add(model)
            self.consec_anon_fail.pop(model, None)

    def is_keyed(self, model: str) -> bool:
        return model in self.keyed

    def try_probe_recover(self, model: str, now=None) -> bool:
        now = now or time.time()
        if model not in self.keyed:
            return False
        last = self.last_probe.get(model, 0)
        if now - last < self.probe_seconds:
            return False
        self.last_probe[model] = now
        return True

    def recover(self, model: str):
        self.keyed.discard(model)
        self.last_probe.pop(model, None)
        self.consec_anon_fail.pop(model, None)


def load_api_keys(path: str):
    path = path or os.environ.get("ZEN_API_KEYS_FILE", "")
    if not path or not os.path.isfile(path):
        return []
    keys = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                keys.append(line)
    except OSError:
        pass
    return keys
