# Blockchain-Based Academic Certificate Verification

A decentralized academic certificate issuing and verification system using **SHA-256 hashing** and **ECDSA (NIST-P256) digital signatures**, built in **Python with Flask** and a lightweight local Blockchain ledger.

## Features

- Cryptographically secure **ECDSA key pair generation**
- Certificate **hashing using SHA-256**
- **Signing certificate hash** with issuer private key
- Storing certificate proof on a **local Blockchain ledger**
- Verifying certificate **integrity + signature + blockchain record**
- Web UI for `/issue` and `/verify` endpoints
- Unit tests implemented using **PyTest**


# Why Blockchain + ECDSA?

- Prevents certificate tampering (immutable ledger)
- No central dependency — decentralized trust model
- Signature verification ensures **authenticity**
- Hashing ensures **file integrity**


## Project Structure

```plaintext
Certificate_Verification_Project

1)app.py                # Flask Web App (Issue + Verify certificates UI)
2)blockchain.py         # Lightweight Blockchain ledger
3)crypto_utils.py       # Key generation, hashing, signing, signature verification
4)templates/
a)issue.html        # Upload form for issuing certificates
b)verify.html       # Upload form for verifying certificates
tests/
test_crypto.py    # Signature & verification unit tests

Setup & Run the Project Locally

## Clone the Repo
```bash
   git clone <repo_url>
   cd Certificate_Verification_Project
   ```

## Create & Activate Virtual Environment (Windows)
   ```bash
   python -m venv venv
   source venv/bin/activate  # or venv\Scripts\activate on Windows
   pip install -r requirements.txt
   ```

Tests
Run tests with pytest:
```bash
pytest -q
   ```
## Start Flask App
```bash
python app.py
   ```
## Open in Browser

http://127.0.0.1:5000/issue
http://127.0.0.1:5000/verify


## Usage
## Issue Certificate (/issue)

Upload certificate file

System computes SHA-256 hash

Issuer private key signs the hash (ECDSA)

Signed hash + metadata stored on Blockchain

## Verify Certificate (/verify)

Upload same certificate file

System recomputes SHA-256 hash

Verifies the ECDSA signature using issuer public key

Confirms record existence on Blockchain

Returns valid or invalid

## Notes
- This project is a demo for coursework. Do NOT use in production without fixing key-management, persistence, security, and network design.
