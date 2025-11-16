"""
AES Encryption & Decryption Utilities.

- Implements AES-128 in ECB mode.
- Uses PKCS#7 padding for block alignment.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

AES_BLOCK_SIZE_BYTES = 128 // 8

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypts plaintext using AES-128-ECB with PKCS#7 padding.
    
    Args:
        key: The 16-byte AES-128 key.
        plaintext: The data to encrypt (bytes).
        
    Returns:
        The encrypted ciphertext (bytes).
    """
    if len(key) != 16:
        raise ValueError("AES key must be 16 bytes (for AES-128).")
    
    # 1. Create a PKCS#7 padder
    padder = padding.PKCS7(AES_BLOCK_SIZE_BYTES * 8).padder()
    
    # 2. Apply padding to the plaintext
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    # 3. Create AES-128 ECB cipher object
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # 4. Encrypt the padded data
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext

def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypts ciphertext using AES-128-ECB and unpads with PKCS#7.
    
    Args:
        key: The 16-byte AES-128 key.
        ciphertext: The data to decrypt (bytes).
        
    Returns:
        The original plaintext (bytes).
    """
    if len(key) != 16:
        raise ValueError("AES key must be 16 bytes (for AES-128).")
    
    try:
        # 1. Create AES-128 ECB cipher object
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # 2. Decrypt the data
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 3. Create a PKCS#7 unpadder
        unpadder = padding.PKCS7(AES_BLOCK_SIZE_BYTES * 8).unpadder()
        
        # 4. Remove padding
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
        
    except ValueError:
        # This error is commonly raised if the key is wrong or data is corrupt,
        # leading to invalid padding.
        raise ValueError("Decryption failed. Data may be corrupt or key is incorrect.")