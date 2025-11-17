#!/usr/bin/env python3
"""Test RSA digital signature implementation."""

from app.crypto.sign import RSASignature

def test_rsa_signature():
    """Test signing and verification."""
    
    # Load keys
    client_key = RSASignature.load_private_key('certs/client.key')
    client_pub = RSASignature.load_public_key('certs/client.crt')
    
    # Test data
    test_message = b"Hello SecureChat!"
    
    print("=" * 60)
    print("🔐 RSA Digital Signature Test")
    print("=" * 60)
    
    # Sign with private key
    print("\n1️⃣  Signing message with client private key...")
    signature = RSASignature.sign(test_message, client_key)
    print(f"   Message: {test_message}")
    print(f"   Signature (hex): {signature[:64]}...")
    print(f"   Signature length: {len(signature)} chars")
    
    # Verify with public key
    print("\n2️⃣  Verifying signature with client certificate...")
    is_valid = RSASignature.verify(test_message, signature, client_pub)
    print(f"   ✅ Signature valid: {is_valid}")
    
    # Test tampering detection
    print("\n3️⃣  Testing tampering detection...")
    tampered_message = b"Hello Hacker!"
    is_valid_tampered = RSASignature.verify(tampered_message, signature, client_pub)
    print(f"   ❌ Tampered message valid: {is_valid_tampered}")
    
    # Test with server certificate
    print("\n4️⃣  Cross-verification (sign with client, verify with server fails)...")
    server_pub = RSASignature.load_public_key('certs/server.crt')
    is_valid_cross = RSASignature.verify(test_message, signature, server_pub)
    print(f"   ❌ Cross-verification valid: {is_valid_cross}")
    
    print("\n" + "=" * 60)
    print("✅ RSA signature test complete!")
    print("=" * 60)

if __name__ == '__main__':
    test_rsa_signature()
