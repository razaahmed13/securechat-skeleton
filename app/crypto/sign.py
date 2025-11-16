"""
RSA Digital Signature Utilities.

- sign_hash: Signs a pre-computed hash with an RSA private key.
- verify_signature: Verifies a signature against a pre-computed hash
  and an RSA public key.
"""

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

def sign_hash(private_key: rsa.RsaPrivateKey, hash_bytes: bytes) -> bytes:
    """
    Signs a pre-computed hash using RSA-PSS.
    
    Args:
        private_key: The RSA private key object.
        hash_bytes: The 32-byte SHA-256 hash to be signed.
        
    Returns:
        The raw signature bytes.
    """
    if len(hash_bytes) != 32:
        raise ValueError("Input must be a 32-byte SHA-256 hash.")
        
    signature = private_key.sign(
        hash_bytes,
        padding.PKCS1v15(),
        hashes.SHA256() # Note: This must match the hash algorithm used.
    )
    return signature

def verify_signature(
    public_key_or_cert,
    hash_bytes: bytes,
    signature: bytes
) -> bool:
    """
    Verifies a signature against a pre-computed hash.
    
    Args:
        public_key_or_cert: The peer's x509.Certificate or rsa.RsaPublicKey.
        hash_bytes: The 32-byte SHA-256 hash.
        signature: The signature bytes to verify.
        
    Returns:
        True if the signature is valid, False otherwise.
    """
    
    # Extract public key if a certificate is provided
    if isinstance(public_key_or_cert, x509.Certificate):
        public_key = public_key_or_cert.public_key()
    else:
        public_key = public_key_or_cert

    try:
        # Verify the signature
        public_key.verify(
            signature,
            hash_bytes,
            padding.PKCS1v15(),
            hashes.SHA256() # Must match the hash alg used for the hash_bytes
        )
        # If verify() does not raise an exception, the signature is valid.
        return True
    except InvalidSignature:
        # The signature is not valid.
        return False
    except Exception:
        # Other potential errors (e.g., key type mismatch)
        return False