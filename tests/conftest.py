"""
Shared test configuration.

Sets an isolated SQLite database path BEFORE any gateway/auth module is
imported, so tests never touch (or lock) a developer's ./data/gateway.db
and runs are deterministic.
"""

import os
import tempfile

_TMP_DIR = tempfile.mkdtemp(prefix="relay-tests-")
os.environ["MCP_GATEWAY_DB_PATH"] = os.path.join(_TMP_DIR, "gateway.db")
