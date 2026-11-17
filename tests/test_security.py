
import pytest

from basesentinel.core.security import (
    generate_agent_token,
    generate_pairing_code,
    hash_agent_token,
    hash_pairing_code,
    hash_password,
    verify_agent_token,
    verify_pairing_code,
    verify_password,
)


TEST_PEPPER = "test-pepper-for-basesentinel-32bytes"


def test_password_hashing():
    password = "Test-Password-123!"

    password_hash = hash_password(password)

    assert password_hash != password
    assert verify_password(password, password_hash)
    assert not verify_password("wrong-password", password_hash)


def test_agent_token_generation_and_hashing():
    token = generate_agent_token()
    token_hash = hash_agent_token(token)

    assert len(token) >= 32
    assert token_hash != token
    assert verify_agent_token(token, token_hash)
    assert not verify_agent_token("wrong-token-" * 4, token_hash)


def test_pairing_code_generation_and_hashing():
    code = generate_pairing_code()
    code_hash = hash_pairing_code(code, TEST_PEPPER)

    assert len(code) == 14
    assert code.count("-") == 2
    assert verify_pairing_code(code, code_hash, TEST_PEPPER)


def test_pairing_code_normalization():
    code = generate_pairing_code()
    code_hash = hash_pairing_code(code, TEST_PEPPER)

    normalized_code = code.replace("-", "").lower()

    assert verify_pairing_code(
        normalized_code,
        code_hash,
        TEST_PEPPER,
    )


def test_pairing_code_requires_correct_pepper():
    code = generate_pairing_code()
    code_hash = hash_pairing_code(code, TEST_PEPPER)

    assert not verify_pairing_code(
        code,
        code_hash,
        "another-test-pepper-value-123456",
    )


def test_invalid_pairing_code():
    with pytest.raises(ValueError):
        hash_pairing_code("INVALID-CODE", TEST_PEPPER)


def test_short_pepper_is_rejected():
    code = generate_pairing_code()

    with pytest.raises(ValueError):
        hash_pairing_code(code, "short")
