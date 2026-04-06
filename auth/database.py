"""
SQLite Database Storage for MCP Gateway

This module provides persistent storage for:
- OAuth clients (client_id, client_secret, registration info)
- User credentials (JWT tokens for MCP clients)
- Third-party tokens (GitHub, Slack, Linear, etc.)

Schema:
    - oauth_clients: Registered OAuth applications
    - user_credentials: User JWT tokens (for MCP client auth)
    - connector_tokens: Third-party tokens per user per connector
    - auth_codes: OAuth authorization codes
"""

import sqlite3
import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
import logging

# Import encryption utilities
from .encryption import encrypt_data, decrypt_data

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("MCP_GATEWAY_DB_PATH", "data/gateway.db")


def get_db_path() -> Path:
    """Get database path, creating data directory if needed."""
    path = Path(DB_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def init_db() -> sqlite3.Connection:
    """Initialize database with schema."""
    conn = sqlite3.connect(get_db_path())
    conn.row_factory = sqlite3.Row
    
    # Users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            hashed_password TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # OAuth Clients table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id TEXT PRIMARY KEY,
            client_name TEXT NOT NULL,
            client_secret TEXT,
            redirect_uris TEXT NOT NULL,
            is_confidential INTEGER DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    
    # User Credentials (JWT tokens for MCP clients)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS user_credentials (
            user_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            access_token TEXT NOT NULL,
            refresh_token TEXT,
            token_type TEXT DEFAULT 'Bearer',
            expires_at TEXT NOT NULL,
            scope TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (user_id, client_id)
        )
    """)
    
    # Connector Tokens (Third-party tokens per user)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS connector_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            connector_name TEXT NOT NULL,
            token TEXT NOT NULL,
            token_type TEXT DEFAULT 'Bearer',
            refresh_token TEXT,
            expires_at TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, connector_name)
        )
    """)
    
    # Authorization Codes (for OAuth flow)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS auth_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id TEXT,
            redirect_uri TEXT NOT NULL,
            scope TEXT,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    
    # Revoked Tokens (for token revocation)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            jti TEXT PRIMARY KEY,
            revoked_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    
    # Create indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_connector_tokens_user ON connector_tokens(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_connector_tokens_connector ON connector_tokens(connector_name)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_user_creds_user ON user_credentials(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON auth_codes(expires_at)")
    
    # OAuth state table for connector OAuth (persisted, not in-memory)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS oauth_states (
            state TEXT PRIMARY KEY,
            connector TEXT NOT NULL,
            user_id TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_oauth_states_expires ON oauth_states(expires_at)")
    
    # User API Keys (for MCP client authentication)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS api_keys (
            key TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            name TEXT NOT NULL,
            last_used_at TEXT,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            is_active INTEGER DEFAULT 1
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active)")
    
    # Add is_admin column to users if not exists
    try:
        conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # Column already exists
    
    # Connector Permissions (granular tool access per user)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS connector_permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            connector_name TEXT NOT NULL,
            tools TEXT NOT NULL,  -- JSON array of allowed tool names, or null for all
            is_default INTEGER DEFAULT 0,  -- 1 if this is a default permission for new users
            created_by TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(user_id, connector_name)
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_conn_perms_user ON connector_permissions(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_conn_perms_connector ON connector_permissions(connector_name)")
    
    # Access Requests (user requests for connector access)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS access_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            connector_name TEXT NOT NULL,
            requested_tools TEXT,  -- JSON array of requested tools, null for all
            reason TEXT,
            status TEXT DEFAULT 'pending',  -- pending, approved, rejected
            requested_at TEXT NOT NULL,
            reviewed_by TEXT,
            reviewed_at TEXT,
            review_note TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_access_req_user ON access_requests(user_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_access_req_status ON access_requests(status)")

    # Installed Backends (admin-installed backends with global access)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS installed_backends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backend_id TEXT UNIQUE NOT NULL,
            backend_name TEXT NOT NULL,
            backend_type TEXT NOT NULL,  -- 'mcp_stdio', 'mcp_http', 'api_rest', 'api_graphql'
            client_id TEXT NOT NULL,
            client_secret TEXT NOT NULL,
            config TEXT NOT NULL,  -- JSON config for backend (url, base_url, etc.)
            enabled INTEGER DEFAULT 1,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_installed_backends_id ON installed_backends(backend_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_installed_backends_enabled ON installed_backends(enabled)")
    
    conn.commit()
    logger.info(f"Database initialized at {get_db_path()}")
    
    return conn


def get_connection() -> sqlite3.Connection:
    """Get database connection (creates if needed)."""
    conn = sqlite3.connect(get_db_path(), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


# -----------------------------------------------------------------------------
# OAuth Client Operations
# -----------------------------------------------------------------------------

def save_oauth_client(
    client_id: str,
    client_name: str,
    client_secret: Optional[str],
    redirect_uris: List[str],
    is_confidential: bool = True,
) -> None:
    """Save or update OAuth client."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    # Encrypt client secret if provided
    encrypted_secret = encrypt_data(client_secret) if client_secret else None
    conn.execute("""
        INSERT OR REPLACE INTO oauth_clients 
        (client_id, client_name, client_secret, redirect_uris, is_confidential, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (client_id, client_name, encrypted_secret, json.dumps(redirect_uris), 
          1 if is_confidential else 0, now, now))
    conn.commit()


def get_oauth_client(client_id: str) -> Optional[Dict[str, Any]]:
    """Get OAuth client by ID."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM oauth_clients WHERE client_id = ?", (client_id,)
    ).fetchone()
    if not row:
        return None
    return {
        "client_id": row["client_id"],
        "client_name": row["client_name"],
        "client_secret": decrypt_data(row["client_secret"]) if row["client_secret"] else None,
        "redirect_uris": json.loads(row["redirect_uris"]),
        "is_confidential": bool(row["is_confidential"]),
    }


def get_oauth_client_by_secret(client_id: str, client_secret: str) -> Optional[Dict[str, Any]]:
    """Get OAuth client by ID and verify secret."""
    conn = get_connection()
    # Get the stored encrypted secret and decrypt it for comparison
    row = conn.execute(
        "SELECT * FROM oauth_clients WHERE client_id = ?", 
        (client_id,)
    ).fetchone()
    if not row:
        return None
    
    # Decrypt the stored secret and compare with provided secret
    stored_secret = decrypt_data(row["client_secret"]) if row["client_secret"] else None
    if stored_secret == client_secret:
        return {
            "client_id": row["client_id"],
            "client_name": row["client_name"],
            "client_secret": stored_secret,
            "redirect_uris": json.loads(row["redirect_uris"]),
            "is_confidential": bool(row["is_confidential"]),
        }
    return None


# -----------------------------------------------------------------------------
# User Credential Operations (JWT tokens)
# -----------------------------------------------------------------------------

def save_user_credential(
    user_id: str,
    client_id: str,
    access_token: str,
    refresh_token: Optional[str],
    expires_at: str,
    scope: Optional[str] = None,
) -> None:
    """Save or update user credential (JWT token)."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    # Encrypt sensitive token fields
    encrypted_access_token = encrypt_data(access_token)
    encrypted_refresh_token = encrypt_data(refresh_token) if refresh_token else None
    conn.execute("""
        INSERT OR REPLACE INTO user_credentials 
        (user_id, client_id, access_token, refresh_token, token_type, expires_at, scope, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, client_id, encrypted_access_token, encrypted_refresh_token, "Bearer", expires_at, scope, now, now))
    conn.commit()


def get_user_credential(user_id: str, client_id: str) -> Optional[Dict[str, Any]]:
    """Get user credential by user_id and client_id."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM user_credentials WHERE user_id = ? AND client_id = ?",
        (user_id, client_id)
    ).fetchone()
    if not row:
        return None
    # Decrypt sensitive token fields
    result = dict(row)
    result["access_token"] = decrypt_data(result["access_token"]) if result["access_token"] else None
    result["refresh_token"] = decrypt_data(result["refresh_token"]) if result["refresh_token"] else None
    return result


def get_user_credentials_by_user(user_id: str) -> List[Dict[str, Any]]:
    """Get all credentials for a user."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM user_credentials WHERE user_id = ?", (user_id,)
    ).fetchall()
    results = []
    for row in rows:
        result = dict(row)
        # Decrypt sensitive token fields
        result["access_token"] = decrypt_data(result["access_token"]) if result["access_token"] else None
        result["refresh_token"] = decrypt_data(result["refresh_token"]) if result["refresh_token"] else None
        results.append(result)
    return results


def delete_user_credential(user_id: str, client_id: str) -> bool:
    """Delete user credential."""
    conn = get_connection()
    cursor = conn.execute(
        "DELETE FROM user_credentials WHERE user_id = ? AND client_id = ?",
        (user_id, client_id)
    )
    conn.commit()
    return cursor.rowcount > 0


# -----------------------------------------------------------------------------
# Connector Token Operations (Third-party tokens)
# -----------------------------------------------------------------------------

def save_connector_token(
    user_id: str,
    connector_name: str,
    token: str,
    token_type: str = "Bearer",
    refresh_token: Optional[str] = None,
    expires_at: Optional[str] = None,
    metadata: Optional[Dict] = None,
) -> None:
    """Save or update connector token for a user."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    # Encrypt sensitive token fields
    encrypted_token = encrypt_data(token)
    encrypted_refresh_token = encrypt_data(refresh_token) if refresh_token else None
    conn.execute("""
        INSERT OR REPLACE INTO connector_tokens 
        (user_id, connector_name, token, token_type, refresh_token, expires_at, metadata, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, connector_name, encrypted_token, token_type, encrypted_refresh_token, expires_at, 
          json.dumps(metadata) if metadata else None, now, now))
    conn.commit()


def get_connector_token(user_id: str, connector_name: str) -> Optional[str]:
    """Get connector token for a user."""
    conn = get_connection()
    row = conn.execute(
        "SELECT token FROM connector_tokens WHERE user_id = ? AND connector_name = ?",
        (user_id, connector_name)
    ).fetchone()
    if row and row["token"]:
        return decrypt_data(row["token"])
    return None


def get_connector_token_full(user_id: str, connector_name: str) -> Optional[Dict[str, Any]]:
    """Get full connector token info."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM connector_tokens WHERE user_id = ? AND connector_name = ?",
        (user_id, connector_name)
    ).fetchone()
    if row:
        result = dict(row)
        # Decrypt sensitive token fields
        result["token"] = decrypt_data(result["token"]) if result["token"] else None
        result["refresh_token"] = decrypt_data(result["refresh_token"]) if result["refresh_token"] else None
        return result
    return None


def list_user_connectors(user_id: str) -> List[str]:
    """List all connectors with tokens for a user."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT connector_name FROM connector_tokens WHERE user_id = ?",
        (user_id,)
    ).fetchall()
    return [row["connector_name"] for row in rows]


def delete_connector_token(user_id: str, connector_name: str) -> bool:
    """Delete connector token."""
    conn = get_connection()
    cursor = conn.execute(
        "DELETE FROM connector_tokens WHERE user_id = ? AND connector_name = ?",
        (user_id, connector_name)
    )
    conn.commit()
    return cursor.rowcount > 0


# -----------------------------------------------------------------------------
# Auth Code Operations
# -----------------------------------------------------------------------------

def save_auth_code(
    code: str,
    client_id: str,
    user_id: str,
    redirect_uri: str,
    scope: Optional[str],
    expires_at: str,
) -> None:
    """Save authorization code."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT INTO auth_codes 
        (code, client_id, user_id, redirect_uri, scope, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (code, client_id, user_id, redirect_uri, scope, expires_at, now))
    conn.commit()


def get_auth_code(code: str) -> Optional[Dict[str, Any]]:
    """Get authorization code."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM auth_codes WHERE code = ?", (code,)
    ).fetchone()
    if not row:
        return None
    
    # Check expiration
    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        conn.execute("DELETE FROM auth_codes WHERE code = ?", (code,))
        conn.commit()
        return None
    
    return dict(row)


def delete_auth_code(code: str) -> bool:
    """Delete authorization code after use."""
    conn = get_connection()
    cursor = conn.execute("DELETE FROM auth_codes WHERE code = ?", (code,))
    conn.commit()
    return cursor.rowcount > 0


# -----------------------------------------------------------------------------
# Token Revocation
# -----------------------------------------------------------------------------

def revoke_token(jti: str, expires_at: str) -> None:
    """Revoke a token."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT OR REPLACE INTO revoked_tokens (jti, revoked_at, expires_at) VALUES (?, ?, ?)",
        (jti, now, expires_at)
    )
    conn.commit()


def is_token_revoked(jti: str) -> bool:
    """Check if token is revoked."""
    conn = get_connection()
    row = conn.execute(
        "SELECT expires_at FROM revoked_tokens WHERE jti = ?", (jti,)
    ).fetchone()
    if not row:
        return False
    
    # Check if expired
    expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
    if datetime.now(timezone.utc) > expires_at:
        conn.execute("DELETE FROM revoked_tokens WHERE jti = ?", (jti,))
        conn.commit()
        return False
    
    return True


# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------

def cleanup_expired() -> int:
    """Clean up expired tokens and codes. Returns count of cleaned items."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    
    # Clean expired auth codes
    cursor = conn.execute("DELETE FROM auth_codes WHERE expires_at < ?", (now,))
    
    # Clean expired revoked tokens
    conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now,))
    
    conn.commit()
    return cursor.rowcount


# -----------------------------------------------------------------------------
# User Operations
# -----------------------------------------------------------------------------

def create_user(
    user_id: str,
    username: str,
    hashed_password: str,
    email: Optional[str] = None,
    is_admin: bool = False,
) -> Optional[Dict[str, Any]]:
    """Create a new user. Returns None if username or email already exists."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    try:
        conn.execute("""
            INSERT INTO users (id, username, email, hashed_password, is_active, is_admin, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, ?, ?, ?)
        """, (user_id, username, email, hashed_password, 1 if is_admin else 0, now, now))
        
        # Apply default permissions for non-admin users
        if not is_admin:
            defaults = get_default_permissions()
            for perm in defaults:
                tools_json = json.dumps(perm.get("tools")) if perm.get("tools") else None
                conn.execute("""
                    INSERT OR IGNORE INTO connector_permissions 
                    (user_id, connector_name, tools, is_default, created_at, updated_at)
                    VALUES (?, ?, ?, 1, ?, ?)
                """, (user_id, perm["connector_name"], tools_json, now, now))
            
            # Apply permissions for all installed backends
            installed_backends = list_installed_backends(include_disabled=False)
            for backend in installed_backends:
                conn.execute("""
                    INSERT OR IGNORE INTO connector_permissions 
                    (user_id, connector_name, tools, is_default, created_at, updated_at)
                    VALUES (?, ?, NULL, 0, ?, ?)
                """, (user_id, backend["backend_id"], now, now))
        
        conn.commit()
        return {
            "id": user_id,
            "username": username,
            "email": email,
            "is_active": True,
            "is_admin": is_admin,
        }
    except sqlite3.IntegrityError:
        return None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Get user by username."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "hashed_password": row["hashed_password"],
        "is_active": bool(row["is_active"]),
    }


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Get user by ID."""
    conn = get_connection()
    row = conn.execute(
        "SELECT id, username, email, is_active, is_admin, created_at FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "is_active": bool(row["is_active"]),
        "is_admin": bool(row["is_admin"]) if "is_admin" in row.keys() else False,
        "created_at": row["created_at"],
    }


def update_user(
    user_id: str,
    username: Optional[str] = None,
    email: Optional[str] = None,
    hashed_password: Optional[str] = None,
) -> bool:
    """Update user fields. Returns True if updated successfully."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    
    if username is not None:
        conn.execute(
            "UPDATE users SET username = ?, updated_at = ? WHERE id = ?",
            (username, now, user_id)
        )
    if email is not None:
        conn.execute(
            "UPDATE users SET email = ?, updated_at = ? WHERE id = ?",
            (email, now, user_id)
        )
    if hashed_password is not None:
        conn.execute(
            "UPDATE users SET hashed_password = ?, updated_at = ? WHERE id = ?",
            (hashed_password, now, user_id)
        )
    
    conn.commit()
    return True


def deactivate_user(user_id: str) -> bool:
    """Deactivate a user account."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE users SET is_active = 0, updated_at = ? WHERE id = ?",
        (now, user_id)
    )
    conn.commit()
    return cursor.rowcount > 0


# -----------------------------------------------------------------------------
# OAuth State Operations (for connector OAuth)
# -----------------------------------------------------------------------------

def create_oauth_state(state: str, connector: str, user_id: Optional[str] = None) -> None:
    """Store OAuth state in database."""
    conn = get_connection()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=10)
    conn.execute("""
        INSERT INTO oauth_states (state, connector, user_id, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?)
    """, (state, connector, user_id, now.isoformat(), expires.isoformat()))
    conn.commit()


def get_oauth_state(state: str) -> Optional[Dict[str, Any]]:
    """Get and validate OAuth state from database."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    row = conn.execute(
        "SELECT connector, user_id, expires_at FROM oauth_states WHERE state = ?",
        (state,)
    ).fetchone()
    if not row:
        return None
    if row["expires_at"] < now:
        conn.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
        conn.commit()
        return None
    return {
        "connector": row["connector"],
        "user_id": row["user_id"],
    }


def delete_oauth_state(state: str) -> None:
    """Delete OAuth state after use."""
    conn = get_connection()
    conn.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
    conn.commit()


def cleanup_oauth_states() -> int:
    """Clean up expired OAuth states."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute("DELETE FROM oauth_states WHERE expires_at < ?", (now,))
    conn.commit()
    return cursor.rowcount


# -----------------------------------------------------------------------------
# API Keys
# -----------------------------------------------------------------------------

def create_api_key(user_id: str, name: str, expires_days: Optional[int] = None) -> str:
    """Create a new API key for a user. Returns the key."""
    import secrets
    key = f"relay_{secrets.token_urlsafe(32)}"
    
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    
    if expires_days:
        expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).isoformat()
    else:
        expires_at = None
    
    conn.execute(
        """INSERT INTO api_keys (key, user_id, name, created_at, expires_at)
           VALUES (?, ?, ?, ?, ?)""",
        (key, user_id, name, now, expires_at)
    )
    conn.commit()
    return key


def get_api_key(key: str) -> Optional[Dict[str, Any]]:
    """Get API key details."""
    conn = get_connection()
    row = conn.execute(
        """SELECT key, user_id, name, last_used_at, created_at, expires_at, is_active
           FROM api_keys WHERE key = ? AND is_active = 1""",
        (key,)
    ).fetchone()
    
    if not row:
        return None
    
    # Check expiration
    if row["expires_at"]:
        expires_at = datetime.fromisoformat(row["expires_at"])
        if expires_at < datetime.now(timezone.utc):
            return None
    
    return dict(row)


def list_api_keys(user_id: str) -> List[Dict[str, Any]]:
    """List all API keys for a user."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT key, user_id, name, last_used_at, created_at, expires_at, is_active
           FROM api_keys WHERE user_id = ? ORDER BY created_at DESC""",
        (user_id,)
    ).fetchall()
    return [dict(row) for row in rows]


def delete_api_key(user_id: str, key: str) -> bool:
    """Delete (deactivate) an API key."""
    conn = get_connection()
    cursor = conn.execute(
        "UPDATE api_keys SET is_active = 0 WHERE key = ? AND user_id = ?",
        (key, user_id)
    )
    conn.commit()
    return cursor.rowcount > 0


def update_api_key_last_used(key: str) -> None:
    """Update the last_used_at timestamp for an API key."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute("UPDATE api_keys SET last_used_at = ? WHERE key = ?", (now, key))
    conn.commit()


# -----------------------------------------------------------------------------
# User Admin Functions
# -----------------------------------------------------------------------------

def set_user_admin(user_id: str, is_admin: bool = True) -> bool:
    """Set or unset user as admin."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE users SET is_admin = ?, updated_at = ? WHERE id = ?",
        (1 if is_admin else 0, now, user_id)
    )
    conn.commit()
    return cursor.rowcount > 0


def is_user_admin(user_id: str) -> bool:
    """Check if user is an admin."""
    conn = get_connection()
    row = conn.execute(
        "SELECT is_admin FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    return row and bool(row["is_admin"])


def list_users(is_admin: Optional[bool] = None) -> List[Dict[str, Any]]:
    """List all users, optionally filter by admin status."""
    conn = get_connection()
    if is_admin is None:
        rows = conn.execute(
            "SELECT id, username, email, is_active, is_admin, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT id, username, email, is_active, is_admin, created_at FROM users WHERE is_admin = ? ORDER BY created_at DESC",
            (1 if is_admin else 0,)
        ).fetchall()
    return [dict(row) for row in rows]


# -----------------------------------------------------------------------------
# Connector Permissions (Granular Tool Access)
# -----------------------------------------------------------------------------

def set_connector_permission(
    user_id: str,
    connector_name: str,
    tools: Optional[List[str]] = None,
    is_default: bool = False,
    created_by: Optional[str] = None,
) -> None:
    """Set or update connector permission for a user."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    
    # Get existing permission to merge tools incrementally
    existing_perm = get_connector_permission(user_id, connector_name)
    existing_tools = existing_perm.get("tools") if existing_perm else None
    
    # If tools is None, it means "all tools" - no need to merge
    if tools is None:
        merged_tools = None
    # If existing tools is None, it means user had "all tools" access
    elif existing_tools is None:
        # If user had all tools and now requesting specific tools, 
        # we keep the specific tools (could be seen as restricting)
        merged_tools = tools
    # If both are specific tool lists, merge them (union)
    else:
        # Convert to sets for union operation, then back to list
        merged_tools = list(set(existing_tools) | set(tools))
    
    tools_json = json.dumps(merged_tools) if merged_tools else None
    
    conn.execute("""
        INSERT OR REPLACE INTO connector_permissions 
        (user_id, connector_name, tools, is_default, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (user_id, connector_name, tools_json, 1 if is_default else 0, created_by, now, now))
    conn.commit()


def get_connector_permission(user_id: str, connector_name: str) -> Optional[Dict[str, Any]]:
    """Get connector permission for a user."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM connector_permissions WHERE user_id = ? AND connector_name = ?",
        (user_id, connector_name)
    ).fetchone()
    if not row:
        return None
    return {
        "user_id": row["user_id"],
        "connector_name": row["connector_name"],
        "tools": json.loads(row["tools"]) if row["tools"] else None,
        "is_default": bool(row["is_default"]),
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }


def get_user_permissions(user_id: str) -> List[Dict[str, Any]]:
    """Get all connector permissions for a user."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM connector_permissions WHERE user_id = ?",
        (user_id,)
    ).fetchall()
    return [
        {
            "connector_name": row["connector_name"],
            "tools": json.loads(row["tools"]) if row["tools"] else None,
            "is_default": bool(row["is_default"]),
        }
        for row in rows
    ]


def get_all_user_permissions() -> Dict[str, List[Dict[str, Any]]]:
    """Get all connector permissions for all users (for admin view)."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM connector_permissions ORDER BY user_id, connector_name"
    ).fetchall()
    
    result = {}
    for row in rows:
        user_id = row["user_id"]
        if user_id not in result:
            result[user_id] = []
        result[user_id].append({
            "connector_name": row["connector_name"],
            "tools": json.loads(row["tools"]) if row["tools"] else None,
            "is_default": bool(row["is_default"]),
        })
    return result


def get_default_permissions() -> List[Dict[str, Any]]:
    """Get all default connector permissions."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM connector_permissions WHERE is_default = 1"
    ).fetchall()
    return [
        {
            "connector_name": row["connector_name"],
            "tools": json.loads(row["tools"]) if row["tools"] else None,
        }
        for row in rows
    ]


def delete_connector_permission(user_id: str, connector_name: str) -> bool:
    """Delete connector permission for a user."""
    conn = get_connection()
    cursor = conn.execute(
        "DELETE FROM connector_permissions WHERE user_id = ? AND connector_name = ?",
        (user_id, connector_name)
    )
    conn.commit()
    return cursor.rowcount > 0


def apply_default_permissions(user_id: str, created_by: Optional[str] = None) -> None:
    """Apply default permissions to a new user."""
    defaults = get_default_permissions()
    for perm in defaults:
        set_connector_permission(
            user_id=user_id,
            connector_name=perm["connector_name"],
            tools=perm.get("tools"),
            is_default=False,
            created_by=created_by,
        )


# -----------------------------------------------------------------------------
# Access Requests
# -----------------------------------------------------------------------------

def create_access_request(
    user_id: str,
    connector_name: str,
    requested_tools: Optional[List[str]] = None,
    reason: Optional[str] = None,
) -> int:
    """Create a new access request. Returns request ID."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    tools_json = json.dumps(requested_tools) if requested_tools else None
    
    cursor = conn.execute("""
        INSERT INTO access_requests 
        (user_id, connector_name, requested_tools, reason, status, requested_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)
    """, (user_id, connector_name, tools_json, reason, now, now, now))
    conn.commit()
    return cursor.lastrowid


def get_access_request(request_id: int) -> Optional[Dict[str, Any]]:
    """Get access request by ID."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM access_requests WHERE id = ?", (request_id,)
    ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "user_id": row["user_id"],
        "connector_name": row["connector_name"],
        "requested_tools": json.loads(row["requested_tools"]) if row["requested_tools"] else None,
        "reason": row["reason"],
        "status": row["status"],
        "requested_at": row["requested_at"],
        "reviewed_by": row["reviewed_by"],
        "reviewed_at": row["reviewed_at"],
        "review_note": row["review_note"],
    }


def get_user_access_requests(user_id: str) -> List[Dict[str, Any]]:
    """Get all access requests for a user."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM access_requests WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    return [
        {
            "id": row["id"],
            "connector_name": row["connector_name"],
            "requested_tools": json.loads(row["requested_tools"]) if row["requested_tools"] else None,
            "reason": row["reason"],
            "status": row["status"],
            "requested_at": row["requested_at"],
            "reviewed_by": row["reviewed_by"],
            "reviewed_at": row["reviewed_at"],
            "review_note": row["review_note"],
        }
        for row in rows
    ]


def get_pending_access_requests() -> List[Dict[str, Any]]:
    """Get all pending access requests."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT ar.*, u.username 
           FROM access_requests ar 
           JOIN users u ON ar.user_id = u.id 
           WHERE ar.status = 'pending' 
           ORDER BY ar.requested_at DESC"""
    ).fetchall()
    return [
        {
            "id": row["id"],
            "user_id": row["user_id"],
            "username": row["username"],
            "connector_name": row["connector_name"],
            "requested_tools": json.loads(row["requested_tools"]) if row["requested_tools"] else None,
            "reason": row["reason"],
            "status": row["status"],
            "requested_at": row["requested_at"],
        }
        for row in rows
    ]


def get_all_access_requests(status: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all access requests, optionally filter by status."""
    conn = get_connection()
    if status:
        rows = conn.execute(
            """SELECT ar.*, u.username 
               FROM access_requests ar 
               JOIN users u ON ar.user_id = u.id 
               WHERE ar.status = ? 
               ORDER BY ar.created_at DESC""",
            (status,)
        ).fetchall()
    else:
        rows = conn.execute(
            """SELECT ar.*, u.username 
               FROM access_requests ar 
               JOIN users u ON ar.user_id = u.id 
               ORDER BY ar.created_at DESC"""
        ).fetchall()
    return [
        {
            "id": row["id"],
            "user_id": row["user_id"],
            "username": row["username"],
            "connector_name": row["connector_name"],
            "requested_tools": json.loads(row["requested_tools"]) if row["requested_tools"] else None,
            "reason": row["reason"],
            "status": row["status"],
            "requested_at": row["requested_at"],
            "reviewed_by": row["reviewed_by"],
            "reviewed_at": row["reviewed_at"],
            "review_note": row["review_note"],
        }
        for row in rows
    ]


def review_access_request(
    request_id: int,
    reviewer_user_id: str,
    approved: bool,
    note: Optional[str] = None,
) -> bool:
    """Review an access request (approve or reject)."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    status = "approved" if approved else "rejected"
    
    cursor = conn.execute("""
        UPDATE access_requests 
        SET status = ?, reviewed_by = ?, reviewed_at = ?, review_note = ?, updated_at = ?
        WHERE id = ?
    """, (status, reviewer_user_id, now, note, now, request_id))
    conn.commit()
    
    if cursor.rowcount > 0 and approved:
        # Get the request details to create the permission
        request = get_access_request(request_id)
        if request:
            set_connector_permission(
                user_id=request["user_id"],
                connector_name=request["connector_name"],
                tools=request.get("requested_tools"),
                created_by=reviewer_user_id,
            )
    
    return cursor.rowcount > 0


# -----------------------------------------------------------------------------
# Access Check Helper
# -----------------------------------------------------------------------------

def check_user_tool_access(user_id: str, connector_name: str, tool_name: str) -> bool:
    """
    Check if a user has access to a specific tool on a connector.
    
    Returns True if:
    - User has permission with tools=None (all tools allowed)
    - User has permission with tools containing the specific tool
    - No specific permission exists (allow by default for backward compat)
    
    Returns False if:
    - User has explicit permission that doesn't include the tool
    """
    perm = get_connector_permission(user_id, connector_name)
    
    # If no permission exists, allow access (backward compatibility)
    if perm is None:
        return True
    
    # If tools is None or empty, user has access to all tools
    if perm.get("tools") is None or len(perm.get("tools", [])) == 0:
        return True
    
    # Check if tool is in the allowed list
    return tool_name in perm["tools"]


def get_user_allowed_tools(user_id: str, connector_name: str) -> Optional[List[str]]:
    """Get list of allowed tools for a user on a connector, or None if all allowed."""
    perm = get_connector_permission(user_id, connector_name)
    if perm is None:
        return None  # All tools allowed
    return perm.get("tools")


# -----------------------------------------------------------------------------
# Installed Backends (Admin-installed backends with global access)
# -----------------------------------------------------------------------------

def save_installed_backend(
    backend_id: str,
    backend_name: str,
    backend_type: str,
    client_id: str,
    client_secret: str,
    config: Dict[str, Any],
    created_by: str,
) -> None:
    """Save or update an installed backend."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    encrypted_secret = encrypt_data(client_secret)
    conn.execute("""
        INSERT OR REPLACE INTO installed_backends
        (backend_id, backend_name, backend_type, client_id, client_secret, config, enabled, created_by, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    """, (backend_id, backend_name, backend_type, client_id, encrypted_secret, json.dumps(config), 
          created_by, now, now))
    conn.commit()


def get_installed_backend(backend_id: str) -> Optional[Dict[str, Any]]:
    """Get installed backend by ID."""
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM installed_backends WHERE backend_id = ?",
        (backend_id,)
    ).fetchone()
    if not row:
        return None
    return {
        "id": row["id"],
        "backend_id": row["backend_id"],
        "backend_name": row["backend_name"],
        "backend_type": row["backend_type"],
        "client_id": row["client_id"],
        "client_secret": decrypt_data(row["client_secret"]) if row["client_secret"] else None,
        "config": json.loads(row["config"]),
        "enabled": bool(row["enabled"]),
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_installed_backends(include_disabled: bool = False) -> List[Dict[str, Any]]:
    """List all installed backends."""
    conn = get_connection()
    if include_disabled:
        rows = conn.execute(
            "SELECT * FROM installed_backends ORDER BY created_at DESC"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM installed_backends WHERE enabled = 1 ORDER BY created_at DESC"
        ).fetchall()
    
    return [
        {
            "id": row["id"],
            "backend_id": row["backend_id"],
            "backend_name": row["backend_name"],
            "backend_type": row["backend_type"],
            "client_id": row["client_id"],
            "enabled": bool(row["enabled"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }
        for row in rows
    ]


def delete_installed_backend(backend_id: str) -> bool:
    """Delete an installed backend."""
    conn = get_connection()
    cursor = conn.execute(
        "DELETE FROM installed_backends WHERE backend_id = ?",
        (backend_id,)
    )
    conn.commit()
    return cursor.rowcount > 0


def set_backend_enabled(backend_id: str, enabled: bool) -> bool:
    """Enable or disable an installed backend."""
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "UPDATE installed_backends SET enabled = ?, updated_at = ? WHERE backend_id = ?",
        (1 if enabled else 0, now, backend_id)
    )
    conn.commit()
    return cursor.rowcount > 0