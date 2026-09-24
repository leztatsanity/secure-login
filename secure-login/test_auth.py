import pytest
from auth import AuthService, ValidationError, GENERIC_ERROR, LOCKED_ERROR


@pytest.fixture
def service():
    s = AuthService()
    s.register("alice", "CorrectHorse1!")
    return s


# 1. Valid login
def test_valid_login_returns_token(service):
    result = service.login("alice", "CorrectHorse1!")
    assert result["success"] is True
    assert result["token"]


# 2. Bad username
def test_bad_username_rejected_gracefully(service):
    result = service.login("nobody", "whatever1")
    assert result["success"] is False
    assert result["error"] == GENERIC_ERROR


# 3. Wrong password increments counter
def test_wrong_password_increments_failed_attempts(service):
    result = service.login("alice", "wrongpass")
    assert result["success"] is False
    assert service.get_failed_attempts("alice") == 1


# 4. Account lockout after 3 failures (even correct password blocked)
def test_account_locks_after_three_failures(service):
    for _ in range(3):
        service.login("alice", "wrongpass")
    assert service.is_locked("alice") is True
    result = service.login("alice", "CorrectHorse1!")
    assert result["success"] is False
    assert result["error"] == LOCKED_ERROR


# 5. SQL injection attempt
@pytest.mark.parametrize("payload", ["admin' --", "' OR '1'='1", "' OR 1=1 --"])
def test_sql_injection_is_rejected_safely(service, payload):
    with pytest.raises(ValidationError):
        service.login(payload, "anything")
    # DB still intact and no login granted
    assert service.login("alice", "CorrectHorse1!")["success"] is True


def test_sql_injection_in_password_does_not_bypass_login(service):
    result = service.login("alice", "' OR '1'='1")
    assert result["success"] is False


# 6. Empty username
def test_empty_username_raises_validation_error(service):
    with pytest.raises(ValidationError, match="Username is required"):
        service.login("", "CorrectHorse1!")


# 7. Empty password
def test_empty_password_raises_validation_error(service):
    with pytest.raises(ValidationError, match="Password is required"):
        service.login("alice", "")


# 8. Both blank: blocked before touching the database
def test_both_blank_blocked_before_db_access(service, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("Database must not be queried for blank input")

    monkeypatch.setattr(service, "_find_user", fail)
    with pytest.raises(ValidationError):
        service.login("", "")


# Extra tests to keep coverage high
def test_successful_login_resets_failed_attempts(service):
    service.login("alice", "wrong")
    service.login("alice", "CorrectHorse1!")
    assert service.get_failed_attempts("alice") == 0


def test_unknown_user_helpers(service):
    assert service.get_failed_attempts("ghost") is None
    assert service.is_locked("ghost") is False


def test_database_error_does_not_leak_internals(service, monkeypatch):
    import sqlite3

    def boom(*args, **kwargs):
        raise sqlite3.OperationalError("secret table details")

    monkeypatch.setattr(service, "_find_user", boom)
    result = service.login("alice", "CorrectHorse1!")
    assert result["success"] is False
    assert "secret" not in result["error"]
