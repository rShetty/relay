"""
Tests for the per-user/per-tool permission layer (issue #17).

Covers ``check_user_tool_access`` (the enforcement primitive used before
dispatching connector tool calls) plus the underlying permission CRUD:
- No permission row  -> allow (backward compatibility)
- tools=None / []    -> allow all
- explicit tool list -> allow-list semantics
- merge behaviour of ``set_connector_permission``
"""

import pytest

from auth import database as db


@pytest.fixture()
def user_id():
    """Create a throwaway user and return its id."""
    db.init_db()
    uid = "usr_perm_test_1"
    db.create_user(
        user_id=uid,
        username="perm_test_user",
        hashed_password="not-a-real-hash",
    )
    yield uid
    # Cleanup so the shared test DB stays predictable across runs
    conn = db.get_connection()
    conn.execute("DELETE FROM connector_permissions WHERE user_id = ?", (uid,))
    conn.execute("DELETE FROM users WHERE id = ?", (uid,))
    conn.commit()


class TestCheckUserToolAccess:
    def test_no_permission_row_allows_by_default(self, user_id):
        # Backward-compat: users without an explicit permission can call tools.
        assert db.check_user_tool_access(user_id, "github", "github_search") is True

    def test_tools_none_allows_all(self, user_id):
        db.set_connector_permission(user_id, "github", tools=None)
        assert db.check_user_tool_access(user_id, "github", "any_tool_at_all") is True

    def test_explicit_list_is_allowlist(self, user_id):
        db.set_connector_permission(user_id, "github", tools=["read_file"])
        assert db.check_user_tool_access(user_id, "github", "read_file") is True
        assert db.check_user_tool_access(user_id, "github", "delete_repo") is False

    def test_empty_tools_list_allows_all(self, user_id):
        db.set_connector_permission(user_id, "github", tools=[])
        assert db.get_connector_permission(user_id, "github")["tools"] == []
        assert db.check_user_tool_access(user_id, "github", "whatever") is True

    def test_permissions_are_per_connector(self, user_id):
        db.set_connector_permission(user_id, "slack", tools=["post_message"])
        assert db.check_user_tool_access(user_id, "slack", "post_message") is True
        assert db.check_user_tool_access(user_id, "github", "anything") is True

    def test_delete_permission_restores_default_allow(self, user_id):
        db.set_connector_permission(user_id, "linear", tools=["create_issue"])
        assert db.check_user_tool_access(user_id, "linear", "other") is False
        assert db.delete_connector_permission(user_id, "linear") is True
        assert db.get_connector_permission(user_id, "linear") is None
        assert db.check_user_tool_access(user_id, "linear", "other") is True


class TestPermissionStorage:
    def test_get_permission_roundtrip(self, user_id):
        db.set_connector_permission(
            user_id, "github", tools=["a", "b"], created_by="admin_1"
        )
        perm = db.get_connector_permission(user_id, "github")
        assert perm is not None
        assert sorted(perm["tools"]) == ["a", "b"]
        assert perm["created_by"] == "admin_1"

    def test_set_specific_after_specific_merges_union(self, user_id):
        db.set_connector_permission(user_id, "github", tools=["tool_a"])
        db.set_connector_permission(user_id, "github", tools=["tool_b"])
        perm = db.get_connector_permission(user_id, "github")
        assert sorted(perm["tools"]) == ["tool_a", "tool_b"]

    def test_set_none_grants_all_tools(self, user_id):
        db.set_connector_permission(user_id, "github", tools=["tool_a"])
        db.set_connector_permission(user_id, "github", tools=None)
        assert db.get_connector_permission(user_id, "github")["tools"] is None

    def test_restricting_previously_unrestricted_user(self, user_id):
        # All-tools -> specific list narrows access (documented behaviour).
        db.set_connector_permission(user_id, "github", tools=None)
        db.set_connector_permission(user_id, "github", tools=["only_this"])
        assert db.check_user_tool_access(user_id, "github", "only_this") is True
        assert db.check_user_tool_access(user_id, "github", "other_tool") is False

    def test_get_user_allowed_tools(self, user_id):
        assert db.get_user_allowed_tools(user_id, "github") is None
        db.set_connector_permission(user_id, "github", tools=["t1"])
        assert db.get_user_allowed_tools(user_id, "github") == ["t1"]

    def test_get_user_permissions_lists_all_connectors(self, user_id):
        db.set_connector_permission(user_id, "github", tools=["t1"])
        db.set_connector_permission(user_id, "slack", tools=None)
        perms = {p["connector_name"]: p for p in db.get_user_permissions(user_id)}
        assert set(perms) >= {"github", "slack"}
