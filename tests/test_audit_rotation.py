"""
Tests for audit log rotation and retention (issue #8).

- Size-based rotation at max_bytes boundary (default 100MB x 10 files,
  exercised here with a tiny threshold)
- max_files cap: oldest rotation is shifted out
- retention_days deletion of expired rotated files
- Hash chain continuity across rotation boundaries
- Settings wiring (audit_log_max_bytes / max_files / retention_days)
"""

import json
import os
import time

import pytest

from security.middleware import AuditLogger


@pytest.fixture
def audit_path(tmp_path):
    return str(tmp_path / "audit.log")


def _entries(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def _rotated_files(path, max_files):
    return [
        f"{path}.{i}"
        for i in range(1, max_files + 1)
        if os.path.exists(f"{path}.{i}")
    ]


def _log(audit, n=1):
    for _ in range(n):
        audit.log(
            event_type="test_event",
            client_id="client-1234567890",
            user_id="user-1",
            ip_address="10.0.0.1",
            resource="/test",
            action="read",
            success=True,
        )


# -----------------------------------------------------------------------------
# Rotation boundary
# -----------------------------------------------------------------------------

def test_no_rotation_below_boundary(audit_path):
    audit = AuditLogger(audit_path, max_bytes=10_000, max_files=3)
    _log(audit, 5)
    assert os.path.getsize(audit_path) < 10_000
    assert _rotated_files(audit_path, 3) == []
    assert len(_entries(audit_path)) == 5


def test_rotates_when_boundary_exceeded(audit_path):
    # One entry is roughly 300 bytes, so 1000 bytes fits ~3 entries.
    audit = AuditLogger(audit_path, max_bytes=1000, max_files=3)
    for _ in range(50):
        _log(audit)
    assert os.path.exists(audit_path + ".1"), "expected rotation to occur"
    # Active file holds at most one entry over the boundary (rotation runs
    # before each append, so it can exceed max_bytes by at most one entry).
    assert os.path.getsize(audit_path) < 1000 + 400


def test_max_files_cap_drops_oldest(audit_path):
    audit = AuditLogger(audit_path, max_bytes=1000, max_files=3)
    for _ in range(50):
        _log(audit)
    # Only .1-.3 may exist; anything past the cap was shifted out
    rotated = _rotated_files(audit_path, 3)
    assert rotated == [audit_path + ".1", audit_path + ".2", audit_path + ".3"]
    assert not os.path.exists(audit_path + ".4")
    assert not os.path.exists(audit_path + ".5")
    # Every surviving segment is non-empty; total cannot exceed written count
    counts = [len(_entries(p)) for p in rotated] + [len(_entries(audit_path))]
    assert all(c > 0 for c in counts)
    assert sum(counts) <= 50


def test_hash_chain_survives_rotation(audit_path):
    # Large segments + few files so every entry survives the run.
    audit = AuditLogger(audit_path, max_bytes=10_000, max_files=2)
    for _ in range(50):
        _log(audit)
    assert os.path.exists(audit_path + ".1"), "expected at least one rotation"
    # Segments on disk: active file is newest, .1 next-newest, ... .N oldest.
    # Entries within each file are in write order, so chronological order is
    # the oldest segment first, each read naturally.
    segments = [_entries(audit_path)]
    for i in range(1, 3):
        if os.path.exists(f"{audit_path}.{i}"):
            segments.append(_entries(f"{audit_path}.{i}"))
    chrono = []
    for seg in reversed(segments):
        chrono.extend(seg)
    assert len(chrono) == 50
    # Chain: each entry's prev_hash equals the previous entry's hash
    for prev, cur in zip(chrono, chrono[1:]):
        assert cur["prev_hash"] == prev["hash"]
    assert chrono[0]["prev_hash"] == ""


def test_rotation_resumes_chain_from_rotated_file(audit_path):
    """A fresh AuditLogger picks up the hash chain from the last entry on disk."""
    first = AuditLogger(audit_path, max_bytes=500, max_files=3)
    _log(first, 3)
    chain_before = first._last_hash

    second = AuditLogger(audit_path, max_bytes=500, max_files=3)
    assert second._last_hash == chain_before
    _log(second, 1)
    entries = _entries(audit_path)
    assert entries[-1]["prev_hash"] == chain_before


# -----------------------------------------------------------------------------
# Retention
# -----------------------------------------------------------------------------

def test_retention_prunes_expired_rotations(audit_path):
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)
    for i in range(1, 4):
        p = f"{audit_path}.{i}"
        with open(p, "w") as f:
            f.write('{"old": true}\n')
        two_days_ago = time.time() - 2 * 86400
        os.utime(p, (two_days_ago, two_days_ago))
    # Active log stays untouched regardless of age
    with open(audit_path, "w") as f:
        f.write('{"active": true}\n')
    old_active = os.path.getmtime(audit_path)
    os.utime(audit_path, (old_active - 10 * 86400, old_active - 10 * 86400))

    audit = AuditLogger(audit_path, retention_days=1)
    assert not os.path.exists(audit_path + ".1")
    assert not os.path.exists(audit_path + ".2")
    assert not os.path.exists(audit_path + ".3")
    assert os.path.exists(audit_path), "active log must never be pruned"


def test_retention_keeps_recent_rotations(audit_path):
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)
    p = audit_path + ".1"
    with open(p, "w") as f:
        f.write('{"recent": true}\n')
    audit = AuditLogger(audit_path, retention_days=7)
    assert os.path.exists(p)


def test_retention_none_keeps_everything(audit_path):
    os.makedirs(os.path.dirname(audit_path), exist_ok=True)
    p = audit_path + ".1"
    with open(p, "w") as f:
        f.write('{"old": true}\n')
    old = time.time() - 365 * 86400
    os.utime(p, (old, old))
    audit = AuditLogger(audit_path)
    assert os.path.exists(p)


def test_retention_enforced_during_rotation(audit_path):
    """Pruning runs on rotation, not only at startup."""
    audit = AuditLogger(audit_path, max_bytes=10_000, max_files=2, retention_days=30)
    # Simulate an ancient leftover rotation that predates this process.
    # max_files=2 means live rotation only ever touches .1 and .2, so if the
    # stale .3 disappears it can only be due to retention pruning.
    stale = audit_path + ".3"
    with open(stale, "w") as f:
        f.write('{"stale": true}\n')
    ancient = time.time() - 60 * 86400
    os.utime(stale, (ancient, ancient))

    for _ in range(50):
        _log(audit)

    assert os.path.exists(audit_path + ".1"), "expected rotations to occur"
    assert not os.path.exists(stale), "stale rotation should be pruned on rotation"


# -----------------------------------------------------------------------------
# Config wiring
# -----------------------------------------------------------------------------

def test_settings_expose_rotation_fields():
    from config.settings import SecuritySettings

    s = SecuritySettings(
        audit_log_max_bytes=123,
        audit_log_max_files=4,
        audit_log_retention_days=14,
    )
    assert s.audit_log_max_bytes == 123
    assert s.audit_log_max_files == 4
    assert s.audit_log_retention_days == 14


def test_settings_defaults_match_issue_spec():
    from config.settings import SecuritySettings

    s = SecuritySettings()
    assert s.audit_log_max_bytes == 100 * 1024 * 1024  # 100MB
    assert s.audit_log_max_files == 10


def test_server_wires_rotation_settings_into_audit_logger():
    """The server's AuditLogger must receive the rotation settings."""
    import inspect

    import gateway.server as server_module

    src = inspect.getsource(server_module)
    assert src.count("max_bytes=config.security.audit_log_max_bytes") == 2
    assert src.count("max_files=config.security.audit_log_max_files") == 2
    assert src.count("retention_days=config.security.audit_log_retention_days") == 2
