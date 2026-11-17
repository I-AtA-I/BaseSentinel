import hashlib
import hmac
import secrets

def generate_user_session_token() -> str:
    """Generate a cryptographically secure user session token."""
    return secrets.token_urlsafe(32)


def hash_user_session_token(token: str) -> str:
    """Return the SHA-256 digest of a user session token."""
    if (
        not isinstance(token, str)
        or len(token) < 32
        or len(token) > 256
    ):
        raise ValueError("Invalid user session token.")

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)


PAIRING_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
PAIRING_CODE_LENGTH = 12


def hash_password(password: str) -> str:
    """Return a secure password hash."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must not be empty.")

    return generate_password_hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its stored hash."""
    if not isinstance(password, str) or not isinstance(password_hash, str):
        return False

    try:
        return check_password_hash(password_hash, password)
    except (ValueError, TypeError):
        return False


def generate_agent_token() -> str:
    """Generate a cryptographically secure agent token."""
    return secrets.token_urlsafe(32)


def hash_agent_token(token: str) -> str:
    """Return the SHA-256 digest of an agent token."""
    if not isinstance(token, str) or len(token) < 32:
        raise ValueError("Invalid agent token.")

    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def verify_agent_token(token: str, stored_hash: str) -> bool:
    """Compare an agent token with its stored digest."""
    if not isinstance(stored_hash, str):
        return False

    try:
        candidate_hash = hash_agent_token(token)
    except ValueError:
        return False

    return hmac.compare_digest(candidate_hash, stored_hash)


def generate_pairing_code() -> str:
    """Generate a human-readable one-time pairing code."""
    raw_code = "".join(
        secrets.choice(PAIRING_ALPHABET)
        for _ in range(PAIRING_CODE_LENGTH)
    )

    return "-".join(
        raw_code[index:index + 4]
        for index in range(0, PAIRING_CODE_LENGTH, 4)
    )


def _normalize_pairing_code(code: str) -> str:
    """Normalize a pairing code before hashing."""
    if not isinstance(code, str):
        raise ValueError("Invalid pairing code.")

    normalized = "".join(code.split()).replace("-", "").upper()

    if len(normalized) != PAIRING_CODE_LENGTH:
        raise ValueError("Invalid pairing code.")

    if any(character not in PAIRING_ALPHABET for character in normalized):
        raise ValueError("Invalid pairing code.")

    return normalized


def hash_pairing_code(code: str, pepper: str) -> str:
    """Return an HMAC-SHA-256 digest of a pairing code."""
    if not isinstance(pepper, str) or len(pepper.encode("utf-8")) < 32:
        raise ValueError("Pairing code pepper is missing or too short.")

    normalized_code = _normalize_pairing_code(code)

    return hmac.new(
        pepper.encode("utf-8"),
        normalized_code.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_pairing_code(
    code: str,
    stored_hash: str,
    pepper: str,
) -> bool:
    """Verify a pairing code against its stored HMAC digest."""
    if not isinstance(stored_hash, str):
        return False

    try:
        candidate_hash = hash_pairing_code(code, pepper)
    except ValueError:
        return False

    return hmac.compare_digest(candidate_hash, stored_hash)
