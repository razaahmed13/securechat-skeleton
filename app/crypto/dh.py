"""
Diffie-Hellman Key Exchange Utilities.

- Generates DH parameters (p, g).
- Creates a DH key pair (private, public).
- Computes the shared secret (K_s).
- Derives the final 16-byte AES key (K) from K_s.
"""

import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh

# --- Pre-defined DH parameters (Group 14) ---
# Using a standard, well-known group for p and g as suggested
# This is RFC 3526, 2048-bit MODP Group

_p = (
    0xFFFFFFFF_FFFFFFFF_C90FDAA2_2168C234_C4C6628B_80DC1CD1_29024E08_8A67CC74_
    020BBEA6_3B139B22_514A0879_8E3404DD_EF9519B3_CD3A431B_302B0A6D_F25F1437_
    0xF891115_2DCB0563_5B8D293E_94D2AD5E_5168FF5B_BD808622_38D3B367_5A9E6A4C_
    0F1C9F82_C2E0C664_75C30344_A3A36B69_08FF3855_163D9AB2_0E2CA890_DCB88BF2_
    03D2A95E_1907D3A3_A93A275A_D48B4E36_4047562D_5302B695_7CB8D643_941125AE_
CONT_
    0x0A939E8C_530983A8_8932338C_F3BAD627_3970E1FE_378A52F8_A819C64B_76466B34_
    0F0B6C93_87F97A3E_F1416B9B_071F609E_162383A0_06918663_539A5734_8F140C93_
CONTINUE_
    0x23F14E01_18F128D3_D718C9B0_E8AEE3D0_C04E4E6A_2C91A5EB_8B12423E_88846E20_
    04A411F5_68D883B3_B9577D9E_471F1A7E_8C687295_3110E104_813C1C63_4D2B6693_
CONTINUES_
    0x401666B4_42A0693E_4B8ADE55_342C0C15_58332D58_6834A81E_4F038F3E_38244B9C_
    0E63471B_D4709A76_3A90235C_9A637202_773C6F34_E07D27F8_A4D3220F_03A2E8A1_
    0xFFFFFFFF_FFFFFFFF
)

_g = 2

# Store parameters in a reusable object
_dh_parameters = dh.DHParameterNumbers(_p, _g)
_dh_backend = _dh_parameters.parameters()


def generate_dh_keypair() -> tuple[dh.DHPrivateKey, int]:
    """
    Generates a new DH private key and the corresponding public key (A or B).
    
    Returns:
        tuple: (private_key_obj, public_key_int)
    """
    # Generate a private key
    private_key = _dh_backend.generate_private_key()
    
    # Get the public key (y)
    public_key = private_key.public_key()
    
    # Get the integer value of the public key (A = g^a mod p)
    public_key_int = public_key.public_numbers().y
    
    return private_key, public_key_int

def compute_shared_secret(
    private_key: dh.DHPrivateKey,
    peer_public_key_int: int
) -> bytes:
    """
    Computes the shared secret (K_s) using our private key
    and the peer's public key.
    
    Returns:
        bytes: The raw shared secret (K_s).
    """
    # Reconstruct the peer's public key object from the integer
    peer_public_numbers = dh.DHPublicNumbers(peer_public_key_int, _dh_parameters)
    peer_public_key = peer_public_numbers.public_key()
    
    # Compute the shared secret
    shared_secret_bytes = private_key.exchange(peer_public_key)
    
    return shared_secret_bytes

def derive_aes_key(shared_secret: bytes) -> bytes:
    """
    Derives the final 16-byte AES key from the shared secret (K_s).
    
    As per assignment: K = Trunc16(SHA256(big-endian(K_s)))
    """
    
    # 1. Hash the shared secret
    # Note: The 'shared_secret' from `exchange()` is already in
    # a consistent big-endian byte representation.
    hashed_secret = hashlib.sha256(shared_secret).digest()
    
    # 2. Truncate the hash to 16 bytes for AES-128
    aes_key = hashed_secret[:16]
    
    return aes_key