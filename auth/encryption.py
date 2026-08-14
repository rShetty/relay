"""
Encryption utilities for securing sensitive data at rest.
"""
import os
import base64
import logging
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_encryption_key: bytes | None = None


def get_encryption_key() -> bytes:
    """
    Get encryption key from environment variable.

    In production (RELAY_ENVIRONMENT=production), this MUST be set via
    RELAY_ENCRYPTION_KEY. If not set, the server will refuse to start.

    In development, a key is auto-generated and cached in memory (not
    persisted to disk) so it survives only for the process lifetime.
    """
    global _encryption_key

    if _encryption_key is not None:
        return _encryption_key

    key_env = os.getenv("RELAY_ENCRYPTION_KEY")
    if key_env:
        try:
            Fernet(key_env.encode("utf-8"))
            _encryption_key = key_env.encode("utf-8")
            return _encryption_key
        except Exception:
            raise ValueError(
                "RELAY_ENCRYPTION_KEY must be a valid Fernet key "
                "(base64-encoded 32 bytes). Generate with: "
                "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
            )

    env = os.getenv("RELAY_ENVIRONMENT", "development")
    if env == "production":
        raise RuntimeError(
            "RELAY_ENCRYPTION_KEY is required in production. "
            "Generate with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )

    # Development only — ephemeral, not persisted
    _encryption_key = Fernet.generate_key()
    logger.warning(
        "RELAY_ENCRYPTION_KEY not set — using ephemeral key (development only). "
        "Encrypted data will be lost on restart."
    )
    return _encryption_key


def get_cipher() -> Fernet:
    """Get Fernet cipher instance."""
    return Fernet(get_encryption_key())


def encrypt_data(data: str) -> str:
    """Encrypt string data. Returns base64-encoded encrypted data."""
    if not data:
        return data
    cipher = get_cipher()
    encrypted_bytes = cipher.encrypt(data.encode("utf-8"))
    return base64.urlsafe_b64encode(encrypted_bytes).decode("utf-8")


def decrypt_data(encrypted_data: str) -> str:
    """
    Decrypt base64-encoded encrypted data.

    Raises RuntimeError if decryption fails — never silently returns
    ciphertext, which could mask corruption or tampering.
    """
    if not encrypted_data:
        return encrypted_data
    try:
        cipher = get_cipher()
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode("utf-8"))
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        return decrypted_bytes.decode("utf-8")
    except (InvalidToken, Exception) as e:
        logger.error("Decryption failed — data may be corrupted or key mismatch: %s", e)
        raise RuntimeError("Failed to decrypt data — encryption key mismatch or data corruption") from e