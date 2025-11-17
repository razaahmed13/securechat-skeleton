#!/usr/bin/env python3
"""Test Diffie-Hellman key exchange implementation."""

from app.crypto.dh import DiffieHellman, perform_dh_exchange, exchange_public_keys, complete_exchange


def test_dh_exchange():
    """Test a complete DH key exchange between two parties."""
    
    print("=" * 70)
    print("🔐 Diffie-Hellman Key Exchange Test")
    print("=" * 70)
    
    # Step 1: Generate key pairs
    print("\n1️⃣  Generating DH key pairs...")
    alice_private = DiffieHellman.generate_private_key()
    alice_public = DiffieHellman.get_public_key(alice_private)
    print("   ✅ Alice's key pair generated")
    
    bob_private = DiffieHellman.generate_private_key()
    bob_public = DiffieHellman.get_public_key(bob_private)
    print("   ✅ Bob's key pair generated")
    
    # Step 2: Serialize public keys (for transmission)
    print("\n2️⃣  Serializing public keys for transmission...")
    alice_pub_bytes = DiffieHellman.serialize_public_key(alice_public)
    bob_pub_bytes = DiffieHellman.serialize_public_key(bob_public)
    print(f"   Alice's public key (bytes): {len(alice_pub_bytes)} bytes")
    print(f"   Bob's public key (bytes): {len(bob_pub_bytes)} bytes")
    
    # Step 3: Simulate transmission (exchange public keys)
    print("\n3️⃣  Exchanging public keys over network...")
    alice_received_bob_pub = DiffieHellman.deserialize_public_key(bob_pub_bytes)
    bob_received_alice_pub = DiffieHellman.deserialize_public_key(alice_pub_bytes)
    print("   ✅ Public keys exchanged")
    
    # Step 4: Compute shared secrets
    print("\n4️⃣  Computing shared secrets...")
    alice_shared = DiffieHellman.compute_shared_secret(alice_private, alice_received_bob_pub)
    bob_shared = DiffieHellman.compute_shared_secret(bob_private, bob_received_alice_pub)
    print(f"   Alice's shared secret: {alice_shared.hex()[:64]}... ({len(alice_shared)} bytes)")
    print(f"   Bob's shared secret: {bob_shared.hex()[:64]}... ({len(bob_shared)} bytes)")
    
    # Step 5: Verify shared secrets match
    print("\n5️⃣  Verifying shared secrets match...")
    if alice_shared == bob_shared:
        print("   ✅ Shared secrets MATCH! (Agreement successful)")
    else:
        print("   ❌ Shared secrets DON'T MATCH! (Error)")
        return
    
    # Step 6: Derive session keys
    print("\n6️⃣  Deriving session keys using SHA-256...")
    alice_session_key = DiffieHellman.derive_key(alice_shared, key_length=16)
    bob_session_key = DiffieHellman.derive_key(bob_shared, key_length=16)
    print(f"   Alice's session key (hex): {alice_session_key.hex()}")
    print(f"   Bob's session key (hex): {bob_session_key.hex()}")
    print(f"   Session key length: {len(alice_session_key)} bytes (AES-128)")
    
    # Step 7: Verify session keys match
    print("\n7️⃣  Verifying session keys match...")
    if alice_session_key == bob_session_key:
        print("   ✅ Session keys MATCH! (Ready for encryption)")
    else:
        print("   ❌ Session keys DON'T MATCH! (Error)")
        return
    
    # Additional info
    print("\n" + "=" * 70)
    print("📊 DH Parameters:")
    p, g = DiffieHellman.get_parameters()
    print(f"   Generator (g): {g}")
    print(f"   Prime (p): {str(p)[:64]}... ({p.bit_length()} bits)")
    print(f"   RFC 3526 2048-bit MODP Group")
    
    print("\n" + "=" * 70)
    print("✅ DH Key Exchange Test Complete!")
    print("=" * 70)


def test_convenient_functions():
    """Test the convenient wrapper functions."""
    
    print("\n\n" + "=" * 70)
    print("🔐 Diffie-Hellman Convenient Functions Test")
    print("=" * 70)
    
    # Step 1: Alice initiates exchange
    print("\n1️⃣  Alice generates key pair and public key...")
    alice_private = DiffieHellman.generate_private_key()
    alice_public, alice_pub_bytes = exchange_public_keys(alice_private)
    print(f"   Alice's public key size: {len(alice_pub_bytes)} bytes")
    
    # Step 2: Bob generates key pair and public key
    print("\n2️⃣  Bob generates key pair and public key...")
    bob_private = DiffieHellman.generate_private_key()
    bob_public, bob_pub_bytes = exchange_public_keys(bob_private)
    print(f"   Bob's public key size: {len(bob_pub_bytes)} bytes")
    
    # Step 3: Alice completes exchange with Bob's public key
    print("\n3️⃣  Alice computes shared secret...")
    alice_result = complete_exchange(alice_private, bob_pub_bytes)
    print(f"   ✅ Shared secret: {alice_result['shared_secret'].hex()[:64]}...")
    print(f"   ✅ Session key: {alice_result['session_key'].hex()}")
    
    # Step 4: Bob completes exchange with Alice's public key
    print("\n4️⃣  Bob computes shared secret...")
    bob_result = complete_exchange(bob_private, alice_pub_bytes)
    print(f"   ✅ Shared secret: {bob_result['shared_secret'].hex()[:64]}...")
    print(f"   ✅ Session key: {bob_result['session_key'].hex()}")
    
    # Verify they match
    print("\n5️⃣  Verifying agreement...")
    if alice_result['session_key'] == bob_result['session_key']:
        print("   ✅ Session keys match!")
    else:
        print("   ❌ Session keys don't match!")
    
    print("\n" + "=" * 70)
    print("✅ Convenient Functions Test Complete!")
    print("=" * 70)


if __name__ == '__main__':
    test_dh_exchange()
    test_convenient_functions()
