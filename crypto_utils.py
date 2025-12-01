import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.exceptions import InvalidSignature

# 1. SHA-256 of bytes

def sha256_bytes(data: bytes) -> str:
    """Return hex-encoded SHA-256 digest of bytes."""
    return hashlib.sha256(data).hexdigest()

# 2. SHA-256 of a file (used for certificate hashing)
def sha256_file(path: str) -> str:
    """Return hex-encoded SHA-256 digest of a file."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

# 3. Generate ECDSA keypair (P-256, PKCS#8 PEM)
def generate_ecdsa_keypair():
    """
    Generates a new ECDSA keypair (NIST P-256) and returns:
      (private_key_pem_str, public_key_pem_str)

    Private key (PKCS#8):
        -----BEGIN PRIVATE KEY-----
        ...
        -----END PRIVATE KEY-----

    Public key:
        -----BEGIN PUBLIC KEY-----
        ...
        -----END PUBLIC KEY-----
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    return private_pem, public_pem

# 4. Load private/public keys from PEM
def _load_private_key(pem_str: str):
    """Load an EC private key from PKCS#8 PEM."""
    return load_pem_private_key(pem_str.encode(), password=None)


def _load_public_key(pem_str: str):
    """Load an EC public key from PEM."""
    return load_pem_public_key(pem_str.encode())

# 5. Sign message
def sign_message(private_key_pem: str, message: bytes) -> str:
    """
    Sign the given message (bytes) with the given private key PEM.
    Returns signature as hex string.
    """
    private_key = _load_private_key(private_key_pem)

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ValueError("Provided private key is not an EC private key")

    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature.hex()

# 6. Verify signature
def verify_signature(public_key_pem: str, message: bytes, signature_hex: str) -> bool:
    """
    Verify an ECDSA signature (hex) for the given message and public key PEM.
    Returns True if valid, False otherwise.
    """
    try:
        public_key = _load_public_key(public_key_pem)

        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False

        signature = bytes.fromhex(signature_hex)
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False
