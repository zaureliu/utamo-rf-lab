"""Hermetic pytest bootstrap.

The application reads configuration from environment variables at import time
and bootstraps admin credentials on first start. Without an isolated runtime,
a local ``pytest`` run would touch the developer's real database and fail to
log in with the fixture password. These defaults mirror the CI workflow
(.github/workflows/tests.yml) and are ignored when the variable is already
explicitly provided.
"""

from __future__ import annotations

import os
import tempfile

_RUNTIME = os.environ.get("UTAMO_TEST_RUNTIME_DIR") or os.path.join(
    tempfile.mkdtemp(prefix="utamo-rflab-tests-"), "runtime"
)

_DEFAULTS = {
    "UTAMO_RUNTIME_DIR": _RUNTIME,
    "UTAMO_RF_DB_PATH": os.path.join(_RUNTIME, "tests.db"),
    "UTAMO_SMART_SCAN_DIR": os.path.join(_RUNTIME, "smart_scans"),
    "UTAMO_ENVIRONMENT": "testing",
    "UTAMO_ADMIN_USERNAME": "admin",
    "UTAMO_ADMIN_PASSWORD": "test-password",
    "UTAMO_RESET_ADMIN_PASSWORD": "1",
    "UTAMO_PM3_MODE": "ANALYSIS_ONLY",
}

for key, value in _DEFAULTS.items():
    os.environ.setdefault(key, value)
