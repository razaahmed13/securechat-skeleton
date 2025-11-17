#!/usr/bin/env python3
"""Test AES-128 encryption/decryption implementation."""

from app.crypto.aes import AES128, encrypt_message, decrypt_message
import os


def test_aes_basic():
    """Test basic AES-128 encryption and decryption."""
    
    print("=" * 70)
    print("🔐 AES-128 Basic Encryption/Decryption Test")
    print("=" * 70)
    
    # Generate a 16-byte key
    key = os.urandom(16)
    print(f"\n1️⃣  Generated AES-128 key: {key.hex()}")
    
    # Test message
    plaintext = "Hello SecureChat!"
    print(f"2️⃣  Original message: {plaintext}")
    
    # Encrypt
    print(f"\n3️⃣  Encrypting message...")
    ciphertext = AES128.encrypt(plaintext, key)
    print(f"   Ciphertext (hex): {ciphertext}")
    print(f"   Ciphertext length: {len(ciphertext)} chars ({len(ciphertext)//2} bytes)")
    
    # Decrypt
    print(f"\n4️⃣  Decrypting message...")
    decrypted = AES128.decrypt_str(ciphertext, key)
    print(f"   Decrypted: {decrypted}")
    
    # Verify
    print(f"\n5️⃣  Verifying...")
    if decrypted == plaintext:
        print(f"   ✅ Encryption/Decryption successful!")
    else:
        print(f"   ❌ Mismatch! Original: {plaintext}, Got: {decrypted}")
    
    print("\n" + "=" * 70)


def test_aes_different_messages():
    """Test with various message types."""
    
    print("\n" + "=" * 70)
    print("🔐 AES-128 Different Message Types Test")
    print("=" * 70)
    
    key = os.urandom(16)
    
    test_cases = [
        "Short",
        "This is a longer message that will need padding",
        "Message with special chars: !@#$%^&*()",
        "Numbers: 1234567890",
        "Unicode: 你好世界 🔐",
        "",  # Empty string
        "a" * 100,  # Very long message
    ]
    
    for i, plaintext in enumerate(test_cases, 1):
        print(f"\n{i}️⃣  Test case: '{plaintext[:30]}{'...' if len(plaintext) > 30 else ''}' ({len(plaintext)} chars)")
        
        try:
            ciphertext = AES128.encrypt(plaintext, key)
            decrypted = AES128.decrypt_str(ciphertext, key)
            
            if decrypted == plaintext:
                print(f"   ✅ Success")
            else:
                print(f"   ❌ Mismatch")
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    print("\n" + "=" * 70)


def test_aes_tampering():
    """Test tampering detection."""
    
    print("\n" + "=" * 70)
    print("🔐 AES-128 Tampering Detection Test")
    print("=" * 70)
    
    key = os.urandom(16)
    plaintext = "Secret Message"
    
    print(f"\n1️⃣  Original message: {plaintext}")
    
    # Encrypt
    ciphertext = AES128.encrypt(plaintext, key)
    print(f"2️⃣  Ciphertext: {ciphertext}")
    
    # Tamper with ciphertext
    print(f"\n3️⃣  Tampering with ciphertext...")
    tampered = ciphertext[:-2] + "FF"  # Change last byte
    print(f"   Tampered: {tampered}")
    
    # Try to decrypt
    print(f"\n4️⃣  Attempting to decrypt tampered ciphertext...")
    try:
        decrypted = AES128.decrypt_str(tampered, key)
        print(f"   ❌ Decrypted: {decrypted}")
        print(f"   ⚠️  WARNING: Tampered data was decrypted (invalid padding not caught)")
    except ValueError as e:
        print(f"   ✅ Decryption failed (padding validation detected tampering)")
        print(f"   Error: {e}")
    
    print("\n" + "=" * 70)


def test_aes_wrong_key():
    """Test that wrong key fails to decrypt."""
    
    print("\n" + "=" * 70)
    print("🔐 AES-128 Wrong Key Test")
    print("=" * 70)
    
    key1 = os.urandom(16)
    key2 = os.urandom(16)
    plaintext = "Secret Message"
    
    print(f"\n1️⃣  Key 1: {key1.hex()}")
    print(f"2️⃣  Key 2: {key2.hex()}")
    print(f"3️⃣  Message: {plaintext}")
    
    # Encrypt with key1
    ciphertext = AES128.encrypt(plaintext, key1)
    print(f"\n4️⃣  Encrypted with key1: {ciphertext[:64]}...")
    
    # Try to decrypt with key2
    print(f"\n5️⃣  Attempting to decrypt with key2...")
    try:
        decrypted = AES128.decrypt_str(ciphertext, key2)
        print(f"   ❌ Decrypted: {decrypted}")
        print(f"   ⚠️  WARNING: Wrong key decrypted the message!")
    except Exception as e:
        print(f"   ✅ Decryption with wrong key failed")
        print(f"   Error: {type(e).__name__}: {e}")
    
    print("\n" + "=" * 70)


def test_aes_padding():
    """Test PKCS#7 padding behavior."""
    
    print("\n" + "=" * 70)
    print("🔐 AES-128 PKCS#7 Padding Test")
    print("=" * 70)
    
    test_cases = [
        (b"", 16),          # Empty: needs 16 bytes of padding
        (b"a", 16),         # 1 byte: needs 15 bytes of padding
        (b"ab", 16),        # 2 bytes: needs 14 bytes of padding
        (b"a" * 16, 16),    # 16 bytes: needs full block of padding
        (b"a" * 32, 16),    # 32 bytes: needs full block of padding
    ]
    
    for plaintext, block_size in test_cases:
        print(f"\n1️⃣  Plaintext: {len(plaintext)} bytes")
        
        # Test padding
        padded = AES128.pad(plaintext, block_size)
        print(f"2️⃣  After padding: {len(padded)} bytes")
        print(f"   Padding length: {padded[-1]} byte(s)")
        
        # Test unpadding
        unpadded = AES128.unpad(padded, block_size)
        
        if unpadded == plaintext:
            print(f"3️⃣  ✅ Padding/unpadding successful")
        else:
            print(f"3️⃣  ❌ Mismatch after padding/unpadding")
    
    print("\n" + "=" * 70)


def test_convenience_functions():
    """Test convenience functions."""
    
    print("\n" + "=" * 70)
    print("🔐 AES-128 Convenience Functions Test")
    print("=" * 70)
    
    key = os.urandom(16)
    plaintext = "Using convenience functions!"
    
    print(f"\n1️⃣  Message: {plaintext}")
    
    # Encrypt with convenience function
    print(f"\n2️⃣  Encrypting with encrypt_message()...")
    ciphertext = encrypt_message(plaintext, key)
    print(f"   ✅ Ciphertext: {ciphertext[:64]}...")
    
    # Decrypt with convenience function (as string)
    print(f"\n3️⃣  Decrypting with decrypt_message()...")
    decrypted_str = decrypt_message(ciphertext, key, as_string=True)
    print(f"   ✅ Decrypted (str): {decrypted_str}")
    
    # Decrypt with convenience function (as bytes)
    print(f"\n4️⃣  Decrypting with decrypt_message(as_string=False)...")
    decrypted_bytes = decrypt_message(ciphertext, key, as_string=False)
    print(f"   ✅ Decrypted (bytes): {decrypted_bytes}")
    
    if decrypted_str == plaintext and decrypted_bytes == plaintext.encode('utf-8'):
        print(f"\n5️⃣  ✅ All convenience functions work correctly!")
    
    print("\n" + "=" * 70)


if __name__ == '__main__':
    test_aes_basic()
    test_aes_different_messages()
    test_aes_tampering()
    test_aes_wrong_key()
    test_aes_padding()
    test_convenience_functions()
