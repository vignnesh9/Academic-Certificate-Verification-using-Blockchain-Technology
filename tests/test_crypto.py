import os
import sys

# --- FIX IMPORT PATH ---
# This file is in: project/tests/test_crypto.py
# We want to import from: project/crypto_utils.py

# Get absolute path of this file: .../Certificate_Verification_Project/tests/test_crypto.py
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Get the parent directory (project root)
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)

# Add project root to Python path if not already added
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from crypto_utils import (
    generate_ecdsa_keypair,
    sign_message,
    verify_signature,
    sha256_bytes,
)


def test_signature_and_verify(tmp_path):
    sk_pem, vk_pem = generate_ecdsa_keypair()
    data = b"hello certificate"
    digest = sha256_bytes(data)
    signature = sign_message(sk_pem, digest.encode())
    assert verify_signature(vk_pem, digest.encode(), signature) is True