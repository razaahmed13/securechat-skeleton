#!/usr/bin/env python3
"""Test database and transcript layer implementation."""

from app.storage.db import Database, User
from app.storage.transcript import Transcript
from app.crypto.sign import RSASignature
from pathlib import Path
import time


def test_user_registration():
    """Test user registration."""
    
    print("=" * 70)
    print("🔐 User Registration Test")
    print("=" * 70)
    
    db = Database('securechat.db')
    
    # Test case 1: Register new user
    print(f"\n1️⃣  Registering new user...")
    success, msg = db.register_user('alice@example.com', 'password123')
    
    if success:
        print(f"   ✅ {msg}")
    else:
        print(f"   ❌ {msg}")
    
    # Test case 2: Register another user
    print(f"\n2️⃣  Registering another user...")
    success, msg = db.register_user('bob@example.com', 'secure_password')
    
    if success:
        print(f"   ✅ {msg}")
    else:
        print(f"   ❌ {msg}")
    
    # Test case 3: Try to register duplicate email
    print(f"\n3️⃣  Attempting to register duplicate email...")
    success, msg = db.register_user('alice@example.com', 'different_password')
    
    if not success:
        print(f"   ✅ Registration rejected: {msg}")
    else:
        print(f"   ❌ Duplicate registration allowed!")
    
    print("\n" + "=" * 70)


def test_user_authentication():
    """Test user authentication."""
    
    print("\n" + "=" * 70)
    print("🔐 User Authentication Test")
    print("=" * 70)
    
    db = Database('securechat.db')
    
    # Test case 1: Successful authentication
    print(f"\n1️⃣  Authenticating with correct credentials...")
    success, user, msg = db.authenticate_user('alice@example.com', 'password123')
    
    if success and user:
        print(f"   ✅ Authentication successful")
        print(f"   User ID: {user.user_id}")
        print(f"   Email: {user.email}")
    else:
        print(f"   ❌ {msg}")
    
    # Test case 2: Wrong password
    print(f"\n2️⃣  Authenticating with wrong password...")
    success, user, msg = db.authenticate_user('alice@example.com', 'wrong_password')
    
    if not success:
        print(f"   ✅ Authentication rejected: {msg}")
    else:
        print(f"   ❌ Wrong password accepted!")
    
    # Test case 3: Non-existent user
    print(f"\n3️⃣  Authenticating non-existent user...")
    success, user, msg = db.authenticate_user('nonexistent@example.com', 'password')
    
    if not success:
        print(f"   ✅ Authentication rejected: {msg}")
    else:
        print(f"   ❌ Non-existent user authenticated!")
    
    # Test case 4: Authenticate Bob
    print(f"\n4️⃣  Authenticating Bob...")
    success, user, msg = db.authenticate_user('bob@example.com', 'secure_password')
    
    if success:
        print(f"   ✅ Bob authenticated (ID: {user.user_id})")
    else:
        print(f"   ❌ {msg}")
    
    print("\n" + "=" * 70)


def test_user_lookup():
    """Test user lookup functions."""
    
    print("\n" + "=" * 70)
    print("🔐 User Lookup Test")
    print("=" * 70)
    
    db = Database('securechat.db')
    
    # Test case 1: Get user by email
    print(f"\n1️⃣  Looking up user by email...")
    user = db.get_user_by_email('alice@example.com')
    
    if user:
        print(f"   ✅ Found: {user.email} (ID: {user.user_id})")
    else:
        print(f"   ❌ User not found")
    
    # Test case 2: Get user by ID
    print(f"\n2️⃣  Looking up user by ID...")
    if user:
        found_user = db.get_user_by_id(user.user_id)
        if found_user:
            print(f"   ✅ Found: {found_user.email} (ID: {found_user.user_id})")
        else:
            print(f"   ❌ User not found")
    
    # Test case 3: Check user existence
    print(f"\n3️⃣  Checking if user exists...")
    exists = db.user_exists('bob@example.com')
    print(f"   bob@example.com exists: {exists}")
    
    exists = db.user_exists('nonexistent@example.com')
    print(f"   nonexistent@example.com exists: {exists}")
    
    # Test case 4: List all users
    print(f"\n4️⃣  Listing all users...")
    users = db.list_users()
    print(f"   Total users: {len(users)}")
    for user_id, email in users:
        print(f"   - ID {user_id}: {email}")
    
    print("\n" + "=" * 70)


def test_transcript_session():
    """Test transcript session management."""
    
    print("\n" + "=" * 70)
    print("🔐 Transcript Session Management Test")
    print("=" * 70)
    
    transcript = Transcript('securechat.db')
    
    # Create session
    print(f"\n1️⃣  Creating session...")
    success, session_id, msg = transcript.create_session(user_id=1)
    
    if success:
        print(f"   ✅ {msg}")
    else:
        print(f"   ❌ {msg}")
        return
    
    # Add messages to transcript
    print(f"\n2️⃣  Adding messages to transcript...")
    
    timestamp = int(time.time())
    
    # Message 1
    success, msg_id, msg = transcript.add_message(
        session_id=session_id,
        sender_id=1,
        sequence_number=1,
        timestamp=timestamp,
        ciphertext='0123456789abcdef' * 4,  # 64 chars (32 bytes)
        signature='deadbeef' * 16  # Mock signature
    )
    
    if success:
        print(f"   ✅ Message 1 stored (ID: {msg_id})")
    else:
        print(f"   ❌ {msg}")
    
    # Message 2
    success, msg_id, msg = transcript.add_message(
        session_id=session_id,
        sender_id=2,
        sequence_number=2,
        timestamp=timestamp + 1,
        ciphertext='fedcba9876543210' * 4,
        signature='cafebabe' * 16  # Mock signature
    )
    
    if success:
        print(f"   ✅ Message 2 stored (ID: {msg_id})")
    else:
        print(f"   ❌ {msg}")
    
    # Get session messages
    print(f"\n3️⃣  Retrieving session messages...")
    messages = transcript.get_session_messages(session_id)
    print(f"   Total messages: {len(messages)}")
    
    for msg in messages:
        print(f"   - Seq {msg.sequence_number}: from user {msg.sender_id}")
    
    # Compute transcript hash
    print(f"\n4️⃣  Computing transcript hash...")
    success, transcript_hash, msg = transcript.compute_transcript_hash(session_id)
    
    if success:
        print(f"   ✅ Hash computed: {transcript_hash}")
    else:
        print(f"   ❌ {msg}")
    
    # Close session with receipt
    print(f"\n5️⃣  Closing session with receipt...")
    
    if transcript_hash:
        success, msg = transcript.close_session(
            session_id=session_id,
            session_receipt='abcd1234' * 16  # Mock receipt (signed hash)
        )
        
        if success:
            print(f"   ✅ {msg}")
        else:
            print(f"   ❌ {msg}")
    
    # Retrieve session receipt
    print(f"\n6️⃣  Retrieving session receipt...")
    receipt = transcript.get_session_receipt(session_id)
    
    if receipt:
        print(f"   ✅ Receipt: {receipt}")
    else:
        print(f"   ❌ No receipt found")
    
    print("\n" + "=" * 70)


def test_password_hashing():
    """Test password hashing security."""
    
    print("\n" + "=" * 70)
    print("🔐 Password Hashing Security Test")
    print("=" * 70)
    
    db = Database('securechat.db')
    
    password = "TestPassword123!"
    
    # Generate two hashes of the same password
    print(f"\n1️⃣  Hashing same password twice...")
    hash1, salt1 = db._hash_password(password)
    hash2, salt2 = db._hash_password(password)
    
    print(f"   Hash 1: {hash1[:32]}...")
    print(f"   Hash 2: {hash2[:32]}...")
    print(f"   Salt 1: {salt1[:16]}...")
    print(f"   Salt 2: {salt2[:16]}...")
    
    if hash1 != hash2:
        print(f"   ✅ Different hashes (due to different salts)")
    else:
        print(f"   ❌ Same hashes (salt not working!)")
    
    # Verify password
    print(f"\n2️⃣  Verifying password with correct salt...")
    is_correct = db._verify_password(password, hash1, salt1)
    print(f"   Correct: {is_correct}")
    
    # Try with wrong salt
    print(f"\n3️⃣  Verifying password with wrong salt...")
    is_correct = db._verify_password(password, hash1, salt2)
    print(f"   Correct: {is_correct}")
    
    # Try with wrong password
    print(f"\n4️⃣  Verifying wrong password...")
    is_correct = db._verify_password("WrongPassword", hash1, salt1)
    print(f"   Correct: {is_correct}")
    
    print("\n" + "=" * 70)


if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("🔐 Database and Transcript Layer Tests")
    print("=" * 70 + "\n")
    
    # Delete existing test data to start fresh
    import os
    if os.path.exists('securechat.db'):
        # Backup and reinitialize
        try:
            db = Database('securechat.db')
            db.delete_user(1)
            db.delete_user(2)
        except:
            pass
    
    test_user_registration()
    test_user_authentication()
    test_user_lookup()
    test_password_hashing()
    test_transcript_session()
    
    print("\n" + "=" * 70)
    print("✅ All database and transcript tests complete!")
    print("=" * 70)
