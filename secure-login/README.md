# Secure Login System (Lab #4)

Python login module with lockout, input validation, parameterized SQL, and salted PBKDF2 password hashing.

## Run tests with coverage
    pip install pytest pytest-cov
    pytest --cov=auth --cov-report=term-missing

## Files
- `auth.py` – implementation
- `test_auth.py` – 8 required tests + extras
- `docs/diagrams.md` – sequence and state machine diagrams (Mermaid)
- `docs/reflection.md` – defensive coding reflection
