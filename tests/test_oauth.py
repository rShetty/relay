"""
Tests for OAuth 2.1 authorization-code flow with PKCE (issue #17).

Covers:
- PKCE helper primitives (verifier charset/length, S256 challenge derivation)
- Client registration and strict redirect_uri validation
- Happy-path code exchange -> token pair -> validated access token
- Rejection paths: unknown code, expired code, code reuse, PKCE mismatch,
  client_id mismatch, redirect_uri mismatch
- Refresh-token rotation (old refresh token revoked after use)
"""

import base64
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from auth.oauth import (
    AuthorizationCode,
    JWTManager,
    OAuthProvider,
    generate_code_challenge,
    generate_code_verifier,
    verify_code_verifier,
)


@pytest.fixture()
def provider():
    jwt_manager = JWTManager(
        secret_key="test-secret-oauth-flow",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
    )
    return OAuthProvider(jwt_manager=jwt_manager)


def _register_client(provider):
    return provider.register_client(
        client_name="test-client",
        redirect_uris=["http://localhost/cb"],
    )


def _start_authorization(provider):
    """Register a client and create an authorization code with PKCE."""
    client = _register_client(provider)
    verifier = generate_code_verifier()
    challenge = generate_code_challenge(verifier, "S256")
    code = provider.create_authorization_code(
        client_id=client.client_id,
        redirect_uri="http://localhost/cb",
        code_challenge=challenge,
        code_challenge_method="S256",
        scope="mcp:tools",
    )
    return client, verifier, code


class TestPKCEPrimitives:
    def test_verifier_length_bounds_enforced(self):
        with pytest.raises(ValueError):
            generate_code_verifier(32)
        with pytest.raises(ValueError):
            generate_code_verifier(200)

    def test_verifier_uses_rfc7636_charset(self):
        import string

        verifier = generate_code_verifier(128)
        assert len(verifier) == 128
        allowed = set(string.ascii_letters + string.digits + "-._~")
        assert set(verifier) <= allowed

    def test_s256_challenge_is_base64url_of_sha256(self):
        verifier = "this-is-a-verifier-value-long-enough"
        challenge = generate_code_challenge(verifier, "S256")
        digest = hashlib.sha256(verifier.encode("ascii")).digest()
        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        assert challenge == expected

    def test_plain_method_returns_verifier(self):
        verifier = generate_code_verifier()
        assert generate_code_challenge(verifier, "plain") == verifier

    def test_unsupported_method_rejected(self):
        with pytest.raises(ValueError):
            generate_code_challenge("abc", "MD5")

    def test_verify_roundtrip_and_mismatch(self):
        verifier = generate_code_verifier()
        challenge = generate_code_challenge(verifier, "S256")
        assert verify_code_verifier(verifier, challenge) is True
        assert verify_code_verifier(generate_code_verifier(), challenge) is False


class TestClientRegistration:
    def test_register_and_get_client(self, provider):
        client = _register_client(provider)
        fetched = provider.get_client(client.client_id)
        assert fetched is not None
        assert fetched.client_name == "test-client"
        assert fetched.redirect_uris == ["http://localhost/cb"]

    def test_redirect_uri_exact_match_only(self, provider):
        client = _register_client(provider)
        assert provider.validate_redirect_uri(client.client_id, "http://localhost/cb") is True
        # Prefix / wildcard-ish matches must fail
        assert provider.validate_redirect_uri(client.client_id, "http://localhost/cb/extra") is False
        assert provider.validate_redirect_uri(client.client_id, "http://localhost/cb.evil.com") is False
        assert provider.validate_redirect_uri("unknown-client", "http://localhost/cb") is False


class TestAuthorizationCodeFlow:
    def test_happy_path_exchange_issues_valid_tokens(self, provider):
        client, verifier, code = _start_authorization(provider)

        tokens = provider.exchange_code_for_token(
            code=code,
            code_verifier=verifier,
            client_id=client.client_id,
            redirect_uri="http://localhost/cb",
        )
        assert tokens is not None
        assert tokens.token_type == "Bearer"
        assert tokens.scope == "mcp:tools"

        payload = provider.jwt.decode_token(tokens.access_token)
        assert payload is not None
        assert payload.sub == "demo_user_001"  # demo user bound by default
        assert payload.scope == "mcp:tools"

        info = provider.validate_access_token(tokens.access_token)
        assert info is not None
        assert info["user_id"] == "demo_user_001"

    def test_unknown_code_rejected(self, provider):
        client, _, _ = _start_authorization(provider)
        assert (
            provider.exchange_code_for_token(
                code="not-a-real-code",
                code_verifier=generate_code_verifier(),
                client_id=client.client_id,
                redirect_uri="http://localhost/cb",
            )
            is None
        )

    def test_expired_code_rejected(self, provider):
        client, verifier, code = _start_authorization(provider)
        provider._auth_codes[code].expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        assert (
            provider.exchange_code_for_token(
                code=code,
                code_verifier=verifier,
                client_id=client.client_id,
                redirect_uri="http://localhost/cb",
            )
            is None
        )
        # Expired code is purged
        assert code not in provider._auth_codes

    def test_code_single_use(self, provider):
        client, verifier, code = _start_authorization(provider)
        kwargs = dict(
            code_verifier=verifier,
            client_id=client.client_id,
            redirect_uri="http://localhost/cb",
        )
        first = provider.exchange_code_for_token(code, **kwargs)
        assert first is not None
        # Replay must be rejected
        second = provider.exchange_code_for_token(code, **kwargs)
        assert second is None

    def test_wrong_pkce_verifier_rejected(self, provider):
        client, _verifier, code = _start_authorization(provider)
        attacker_verifier = generate_code_verifier()  # valid shape, wrong value
        assert (
            provider.exchange_code_for_token(
                code=code,
                code_verifier=attacker_verifier,
                client_id=client.client_id,
                redirect_uri="http://localhost/cb",
            )
            is None
        )

    def test_client_id_mismatch_rejected(self, provider):
        other = _register_client(provider)
        _client, verifier, code = _start_authorization(provider)
        assert (
            provider.exchange_code_for_token(
                code=code,
                code_verifier=verifier,
                client_id=other.client_id,
                redirect_uri="http://localhost/cb",
            )
            is None
        )

    def test_redirect_uri_mismatch_rejected(self, provider):
        client, verifier, code = _start_authorization(provider)
        assert (
            provider.exchange_code_for_token(
                code=code,
                code_verifier=verifier,
                client_id=client.client_id,
                redirect_uri="http://attacker.example/cb",
            )
            is None
        )


class TestRefreshRotationAndRevocation:
    def test_refresh_issues_new_pair_and_revokes_old(self, provider):
        client, verifier, code = _start_authorization(provider)
        tokens = provider.exchange_code_for_token(
            code=code,
            code_verifier=verifier,
            client_id=client.client_id,
            redirect_uri="http://localhost/cb",
        )

        old_payload = provider.jwt.decode_token(tokens.refresh_token)
        refreshed = provider.refresh_access_token(tokens.refresh_token, client.client_id)
        assert refreshed is not None
        assert refreshed.access_token != tokens.access_token

        # Old refresh token's jti was revoked during rotation
        assert provider.jwt.is_revoked(old_payload.jti) is True
        # Refreshing again with the same (now revoked) token fails
        assert provider.refresh_access_token(tokens.refresh_token, client.client_id) is None

    def test_refresh_rejects_wrong_client(self, provider):
        client, verifier, code = _start_authorization(provider)
        tokens = provider.exchange_code_for_token(
            code=code,
            code_verifier=verifier,
            client_id=client.client_id,
            redirect_uri="http://localhost/cb",
        )
        other = _register_client(provider)
        assert provider.refresh_access_token(tokens.refresh_token, other.client_id) is None

    def test_revoked_access_token_fails_validation(self, provider):
        client, verifier, code = _start_authorization(provider)
        tokens = provider.exchange_code_for_token(
            code=code,
            code_verifier=verifier,
            client_id=client.client_id,
            redirect_uri="http://localhost/cb",
        )
        assert provider.revoke_token(tokens.access_token) is True
        assert provider.validate_access_token(tokens.access_token) is None

    def test_garbage_token_fails_validation(self, provider):
        assert provider.revoke_token("not-a-jwt") is False
        assert provider.validate_access_token("not-a-jwt") is None


class TestScopeEnforcement:
    def test_validate_access_token_enforces_required_scopes(self, provider):
        jwt = provider.jwt
        token = jwt.create_access_token(user_id="u1", client_id="c1", scope="mcp:tools")
        assert provider.validate_access_token(token, required_scopes=["mcp:tools"]) is not None
        assert (
            provider.validate_access_token(token, required_scopes=["mcp:admin"])
            is None
        )

    def test_expired_access_token_rejected(self, provider):
        token = provider.jwt.create_access_token(
            user_id="u1",
            client_id="c1",
            scope="mcp:tools",
            expires_delta=timedelta(minutes=-5),
        )
        assert provider.jwt.decode_token(token) is None
