# Cryptography Toolkit

[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)  
Replace `OWNER/REPO` in the badge URL with your GitHub owner and repository name to enable the status badge.

Small CLI-focused toolkit with examples for hashing, AES-GCM and RSA encryption, password utilities, and an experimental multi-step cipher pipeline.

Quick start

```
py -m pip install -r requirements.txt
```

```
py main.py
```

```
py modules/encryption.py
py modules/encryption2.py
```
Tests
- Install `pytest` (optional):
```
py -m pip install pytest
- Run tests:
```
py -m pytest -q

Coding_Codex — Cryptography Toolkit

Description
This repository is a small, educational Cryptography Toolkit containing examples and demos for:
- Hashing (SHA-256)
- Symmetric encryption (AES-GCM)
- Asymmetric encryption (RSA)
- Password utilities (zxcvbn strength checks + bcrypt hashing)
- An experimental multi-stage cipher pipeline (`modules/encryption2.py`) that composes text ciphers (Atbash, Substitution, Vigenère) with AES+RSA and a binary→gray encoding stage.

Table of Contents
- Main CLI (`main.py`)
- Modules
	- `modules/encryption.py`
	- `modules/encryption2.py`
	- `modules/hash.py`
	- `modules/password.py`
- Sample files (`sample_files/`)
- Tests (`tests/`)
- Requirements
- How to run
- Technologies Used
- Notes & Security

Main CLI
`main.py` provides a minimal menu-based interactive CLI that demonstrates the modules. It calls functions from `modules/` and prints results. Use this to try the toolkit quickly.

Modules
- `modules/encryption.py`
	- Simple AES-GCM and RSA encrypt/decrypt helpers. AES functions return hex-encoded keys and ciphertexts; RSA helpers return hex ciphertexts.
- `modules/encryption2.py`
	- Experimental pipeline: Atbash → Substitution → Vigenère → AES → RSA → binary → gray. The decryption path mirrors these steps in reverse. This file contains debug prints and helper functions for binary↔gray conversions.
- `modules/hash.py`
	- `hash_file(path)` computes SHA-256 for a file; `verify_integrity(file1, file2)` compares two file hashes.
- `modules/password.py`
	- Uses `zxcvbn` to evaluate password strength and `bcrypt` to hash/verify passwords.

Sample Files
The `sample_files/` folder contains sample data used by demos (e.g., `sample.txt`). Tests may reference these files.

Tests
- Tests live in the `tests/` folder and use `pytest`.
- Quick test files added:
	- `tests/test_hash.py`
	- `tests/test_password.py`
	- `tests/test_encryption.py`

Requirements
- See `requirements.txt`. Main runtime dependencies:
	- `cryptography`
	- `bcrypt`
	- `zxcvbn`

How to run (Windows PowerShell)
1. Install dependencies:
```powershell
py -m pip install -r requirements.txt
```
2. Run the interactive CLI:
```powershell
py main.py
```
3. Run a module demo directly:
```powershell
py modules/encryption.py
py modules/encryption2.py
```
4. Run tests:
```powershell
py -m pytest -q
```

Technologies Used
- Python 3.x
- `cryptography` (AES-GCM, RSA)
- `bcrypt` (password hashing)
- `zxcvbn` (password strength)
- `pytest` (tests)

Notes & Security
- This repository is educational. The code prints keys and ciphertexts for demonstration and is NOT production-grade key management. Do not use in production.
- `encryption2.py` is experimental; it mixes text ciphers and binary encodings and contains debug scaffolding. When refactoring keep hex/byte boundaries explicit.

Made with ❤️ by JumboHACKER24.

- This repo is educational. Do not use it as-is for production cryptography.
