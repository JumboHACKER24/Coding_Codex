# Copilot Instructions — Cryptography Toolkit (Merged)

This file is a merged, up-to-date instruction set for AI coding agents working on this repo. It consolidates the original guidance and the recent 2025-11-23 updates (bug fixes, tests, debug helpers).

1) Quick overview
- Purpose: examples and experiments for hashing, AES-GCM, RSA, password utilities, and an experimental multi-step cipher pipeline (`modules/encryption2.py`).
- Entry point: `main.py` (menu-based CLI).
- Main modules: `modules/encryption.py`, `modules/encryption2.py`, `modules/hash.py`, `modules/password.py`.

2) Architecture and flows
- `main.py` calls small, function-based APIs in `modules/` and prints results.
- AES helpers return hex-encoded key and ciphertext; RSA helpers produce hex ciphertexts. Keep conversions explicit at module boundaries.
- `encryption2.py` composes text ciphers (Atbash, Substitution, Vigenère) with AES+RSA and a binary→gray encoding step; the reverse process must exactly mirror those encodings.

3) Conventions and agent guidance
- Keep functions small and pure where possible; demos can have side-effects in `__main__` blocks but tests should avoid filesystem side-effects.
- Document exact input/output types in docstrings: `bytes`, `hex str`, or `text`.
- Preserve hex/byte semantics when refactoring; many callers (including `main.py`) expect hex strings for keys/ciphertexts.

4) Running and dependencies
- Required runtime packages: `cryptography`, `bcrypt`, `zxcvbn`.
- Install (PowerShell):
```
py -m pip install -r requirements.txt
```
- Run CLI:
```
py main.py
```
- Run demos:
```
py modules/encryption.py
# Copilot Instructions — Cryptography Toolkit (Merged)

This file is a merged, up-to-date instruction set for AI coding agents working on this repo. It consolidates the original guidance and the recent 2025-11-23 updates (bug fixes, tests, debug helpers).

1) Quick overview
- Purpose: examples and experiments for hashing, AES-GCM, RSA, password utilities, and an experimental multi-step cipher pipeline (`modules/encryption2.py`).
- Entry point: `main.py` (menu-based CLI).
- Main modules: `modules/encryption.py`, `modules/encryption2.py`, `modules/hash.py`, `modules/password.py`.

2) Architecture and flows
- `main.py` calls small, function-based APIs in `modules/` and prints results.
- AES helpers return hex-encoded key and ciphertext; RSA helpers produce hex ciphertexts. Keep conversions explicit at module boundaries.
- `encryption2.py` composes text ciphers (Atbash, Substitution, Vigenère) with AES+RSA and a binary→gray encoding step; the reverse process must exactly mirror those encodings.

3) Conventions and agent guidance
- Keep functions small and pure where possible; demos can have side-effects in `__main__` blocks but tests should avoid filesystem side-effects.
- Document exact input/output types in docstrings: `bytes`, `hex str`, or `text`.
- Preserve hex/byte semantics when refactoring; many callers (including `main.py`) expect hex strings for keys/ciphertexts.

4) Running and dependencies
- Required runtime packages: `cryptography`, `bcrypt`, `zxcvbn`.
- Install (PowerShell):
```
py -m pip install -r requirements.txt
```
- Run CLI:
```
py main.py
```
- Run demos:
```
py modules/encryption.py
py modules/encryption2.py
```

5) Tests tools
- Tests use `pytest`; run with `py -m pytest -q`.

6) Recent fixes (2025-11-23)
- Fixed missing final Atbash decryption in `encryption2.py` (decryption now applies Atbash last).
- Fixed `from_binary()` to pad continuous bitstrings to an 8-bit boundary to avoid final-byte corruption.
- Switched `encryption2.py` to hybrid RSA+AES: RSA encrypts the AES key; AES encrypts the message.
- Added debug prints in `encryption2.py` to trace pipeline values during development.

7) Editing checklist for agents
- Before touching `encryption2.py`, run `tests/debug_pipeline.py` to verify text-cipher correctness and `tests/debug_binary_roundtrip.py` for bit conversion.
- When adding features, update tests and document I/O types. Prefer adding small unit tests under `tests/` rather than changing demos.
- Preserve the public API used by `main.py` (hex strings for keys/ciphertext) unless you update all callers.

If you'd like, I can produce a shorter canonical file or scaffold CI to run tests on push — tell me which and I'll apply the change.
