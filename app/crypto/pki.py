"""
PKI and X.509 Certificate Utilities.

- load_ca_cert: Loads the trusted Root CA certificate.
- load_identity: Loads an entity's (client/server) cert and private key.
- verify_certificate: Verifies a peer's certificate against the CA.
"""

import pathlib
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key
)
from cryptography.exceptions import InvalidSignature

# --- Constants ---

# Base directory for certificates
CERT_DIR = pathlib.Path(__file__).parent.parent.parent / "certs"
CA_CERT_FILE = CERT_DIR / "ca_cert.pem"

# --- Public Functions ---

def load_ca_cert() -> x509.Certificate:
    """Loads the Root CA certificate from disk."""
    try:
        with open(CA_CERT_FILE, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        print(f"Error: CA certificate not found at {CA_CERT_FILE}")
        print("Please run 'scripts/gen_ca.py' first.")
        raise
    except Exception as e:
        print(f"Error loading CA certificate: {e}")
        raise

def load_identity(base_path_str: str) -> tuple[x509.Certificate, rsa.RsaPrivateKey]:
    """
    Loads an entity's (client/server) certificate and private key.
    
    Args:
        base_path_str: The base path, e.g., "certs/server" or "certs/client"
    
    Returns:
        A tuple of (certificate, private_key)
    """
    base_path = pathlib.Path(base_path_str)
    cert_file = base_path.with_name(base_path.name + "_cert.pem")
    key_file = base_path.with_name(base_path.name + "_private_key.pem")

    try:
        # Load the certificate
        with open(cert_file, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
            
        # Load the private key
        with open(key_file, "rb") as f:
            private_key = load_pem_private_key(f.read(), password=None)
            
        return cert, private_key

    except FileNotFoundError as e:
        print(f"Error: Identity file not found. Looked for {e.filename}")
        print("Please run 'scripts/gen_cert.py' for both server and client.")
        raise
    except Exception as e:
        print(f"Error loading identity from {base_path_str}: {e}")
        raise

def verify_certificate(
    cert_to_verify: x509.Certificate,
    ca_cert: x509.Certificate,
    expected_cn: str
) -> bool:
    """
    Verifies a received certificate based on assignment requirements.
    
    Checks:
    1. Signature: Was it signed by our trusted CA?
    2. Validity: Is it currently valid (not expired, not future-dated)?
    3. Common Name: Does the CN match what we expect?
    
    Returns:
        True if all checks pass.
    Raises:
        ValueError: If any check fails, with a specific reason.
    """
    
    # 1. Check Signature (Authenticity)
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert_to_verify.signature,
            cert_to_verify.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_to_verify.signature_hash_algorithm,
        )
    except InvalidSignature:
        raise ValueError("BAD_CERT: Signature is invalid. Not signed by our CA.")
    
    # 2. Check Time Validity (Freshness)
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if now_utc < cert_to_verify.not_valid_before_utc:
        raise ValueError(f"BAD_CERT: Certificate is not valid yet (valid from {cert_to_verify.not_valid_before_utc}).")
    if now_utc > cert_to_verify.not_valid_after_utc:
        raise ValueError(f"BAD_CERT: Certificate has expired (expired on {cert_to_verify.not_valid_after_utc}).")

    # 3. Check Common Name (Identity)
    try:
        cn_attribute = cert_to_verify.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        received_cn = cn_attribute.value
        
        if received_cn != expected_cn:
            raise ValueError(f"BAD_CERT: Common Name mismatch. Expected '{expected_cn}', but got '{received_cn}'.")
            
    except (IndexError, AttributeError):
        raise ValueError("BAD_CERT: Certificate does not have a Common Name.")

    # All checks passed
    return True

def get_certificate_cn(cert: x509.Certificate) -> str:
    """Helper function to extract the Common Name (CN) from a certificate."""
    try:
        cn_attribute = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        return cn_attribute.value
    except (IndexError, AttributeError):
        return "UNKNOWN"