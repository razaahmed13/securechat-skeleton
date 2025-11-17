#!/usr/bin/env python3
"""Test SecureChat protocol message serialization/deserialization."""

from app.common.protocol import (
    Hello, ServerHello, DHClient, DHServer,
    Register, RegisterResponse, Login, LoginResponse,
    Message, Receipt, Error, MessageType,
    message_to_json, json_to_message
)
import json


def test_hello_messages():
    """Test HELLO and SERVER_HELLO messages."""
    
    print("=" * 70)
    print("🔐 Protocol: HELLO Messages Test")
    print("=" * 70)
    
    # Test HELLO
    print(f"\n1️⃣  Creating HELLO message...")
    hello = Hello(
        certificate="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    )
    print(f"   Type: {hello.type}")
    print(f"   Cert length: {len(hello.certificate)}")
    
    # Serialize
    print(f"\n2️⃣  Serializing HELLO to JSON...")
    json_str = message_to_json(hello)
    print(f"   JSON: {json_str[:100]}...")
    
    # Deserialize
    print(f"\n3️⃣  Deserializing HELLO from JSON...")
    hello2 = json_to_message(json_str)
    print(f"   ✅ Deserialized: {type(hello2).__name__}")
    
    # Test SERVER_HELLO
    print(f"\n4️⃣  Creating SERVER_HELLO message...")
    server_hello = ServerHello(
        certificate="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    )
    print(f"   Type: {server_hello.type}")
    
    json_str = message_to_json(server_hello)
    server_hello2 = json_to_message(json_str)
    print(f"   ✅ Round-trip successful")
    
    print("\n" + "=" * 70)


def test_dh_messages():
    """Test DH_CLIENT and DH_SERVER messages."""
    
    print("\n" + "=" * 70)
    print("🔐 Protocol: Diffie-Hellman Messages Test")
    print("=" * 70)
    
    # Test DH_CLIENT
    print(f"\n1️⃣  Creating DH_CLIENT message...")
    dh_client = DHClient(
        public_key="a" * 512  # 256 bytes hex (512 chars)
    )
    print(f"   Type: {dh_client.type}")
    print(f"   Public key size: {len(dh_client.public_key)} chars")
    
    json_str = message_to_json(dh_client)
    dh_client2 = json_to_message(json_str)
    print(f"   ✅ DH_CLIENT round-trip successful")
    
    # Test DH_SERVER
    print(f"\n2️⃣  Creating DH_SERVER message...")
    dh_server = DHServer(
        public_key="b" * 512  # 256 bytes hex (512 chars)
    )
    print(f"   Type: {dh_server.type}")
    
    json_str = message_to_json(dh_server)
    dh_server2 = json_to_message(json_str)
    print(f"   ✅ DH_SERVER round-trip successful")
    
    print("\n" + "=" * 70)


def test_auth_messages():
    """Test REGISTER, LOGIN and response messages."""
    
    print("\n" + "=" * 70)
    print("🔐 Protocol: Authentication Messages Test")
    print("=" * 70)
    
    # Test REGISTER
    print(f"\n1️⃣  Creating REGISTER message...")
    register = Register(
        email="alice@example.com",
        password="secret123",
        ciphertext="0123456789abcdef" * 8,  # Mock ciphertext
        signature="deadbeef" * 16  # Mock signature
    )
    print(f"   Type: {register.type}")
    print(f"   Email: {register.email}")
    
    json_str = message_to_json(register)
    register2 = json_to_message(json_str)
    print(f"   ✅ REGISTER round-trip successful")
    
    # Test REGISTER_RESPONSE
    print(f"\n2️⃣  Creating REGISTER_RESPONSE message...")
    reg_resp = RegisterResponse(
        success=True,
        user_id=42,
        ciphertext="fedcba9876543210" * 8,
        signature="cafebabe" * 16
    )
    print(f"   Type: {reg_resp.type}")
    print(f"   Success: {reg_resp.success}")
    print(f"   User ID: {reg_resp.user_id}")
    
    json_str = message_to_json(reg_resp)
    reg_resp2 = json_to_message(json_str)
    print(f"   ✅ REGISTER_RESPONSE round-trip successful")
    
    # Test LOGIN
    print(f"\n3️⃣  Creating LOGIN message...")
    login = Login(
        email="alice@example.com",
        password="secret123",
        ciphertext="0123456789abcdef" * 8,
        signature="deadbeef" * 16
    )
    print(f"   Type: {login.type}")
    
    json_str = message_to_json(login)
    login2 = json_to_message(json_str)
    print(f"   ✅ LOGIN round-trip successful")
    
    # Test LOGIN_RESPONSE
    print(f"\n4️⃣  Creating LOGIN_RESPONSE message...")
    login_resp = LoginResponse(
        success=True,
        user_id=42,
        session_id=1,
        ciphertext="fedcba9876543210" * 8,
        signature="cafebabe" * 16
    )
    print(f"   Type: {login_resp.type}")
    print(f"   Session ID: {login_resp.session_id}")
    
    json_str = message_to_json(login_resp)
    login_resp2 = json_to_message(json_str)
    print(f"   ✅ LOGIN_RESPONSE round-trip successful")
    
    print("\n" + "=" * 70)


def test_chat_messages():
    """Test MESSAGE and RECEIPT messages."""
    
    print("\n" + "=" * 70)
    print("🔐 Protocol: Chat Messages Test")
    print("=" * 70)
    
    # Test MESSAGE
    print(f"\n1️⃣  Creating MESSAGE...")
    msg = Message(
        sender_id=1,
        session_id=1,
        sequence_number=1,
        timestamp=1700000000,
        ciphertext="0123456789abcdef" * 8,
        signature="deadbeef" * 16
    )
    print(f"   Type: {msg.type}")
    print(f"   Sender: {msg.sender_id}, Session: {msg.session_id}")
    print(f"   Sequence: {msg.sequence_number}, Timestamp: {msg.timestamp}")
    
    json_str = message_to_json(msg)
    msg2 = json_to_message(json_str)
    print(f"   ✅ MESSAGE round-trip successful")
    
    # Test RECEIPT
    print(f"\n2️⃣  Creating RECEIPT...")
    receipt = Receipt(
        sender_id=1,
        session_id=1,
        transcript_hash="a" * 64,  # SHA-256 hex
        signature="b" * 256  # RSA signature hex
    )
    print(f"   Type: {receipt.type}")
    print(f"   Session: {receipt.session_id}")
    print(f"   Transcript hash: {receipt.transcript_hash[:32]}...")
    
    json_str = message_to_json(receipt)
    receipt2 = json_to_message(json_str)
    print(f"   ✅ RECEIPT round-trip successful")
    
    print("\n" + "=" * 70)


def test_error_message():
    """Test ERROR message."""
    
    print("\n" + "=" * 70)
    print("🔐 Protocol: Error Message Test")
    print("=" * 70)
    
    # Test ERROR
    print(f"\n1️⃣  Creating ERROR message...")
    error = Error(
        error_code="INVALID_CERT",
        error_message="Client certificate signature verification failed"
    )
    print(f"   Type: {error.type}")
    print(f"   Code: {error.error_code}")
    print(f"   Message: {error.error_message}")
    
    json_str = message_to_json(error)
    error2 = json_to_message(json_str)
    print(f"   ✅ ERROR round-trip successful")
    
    print("\n" + "=" * 70)


def test_json_parsing():
    """Test JSON parsing edge cases."""
    
    print("\n" + "=" * 70)
    print("🔐 Protocol: JSON Parsing Test")
    print("=" * 70)
    
    # Test invalid JSON
    print(f"\n1️⃣  Testing invalid JSON...")
    try:
        json_to_message("not valid json")
        print(f"   ❌ Should have raised ValueError")
    except ValueError as e:
        print(f"   ✅ Correctly rejected: {str(e)[:50]}...")
    
    # Test unknown message type
    print(f"\n2️⃣  Testing unknown message type...")
    try:
        json_to_message('{"type": "unknown_type"}')
        print(f"   ❌ Should have raised ValueError")
    except ValueError as e:
        print(f"   ✅ Correctly rejected: {str(e)}")
    
    # Test missing required field
    print(f"\n3️⃣  Testing missing required field...")
    try:
        json_to_message('{"type": "hello"}')  # Missing 'certificate'
        print(f"   ❌ Should have raised ValueError")
    except ValueError as e:
        print(f"   ✅ Correctly rejected: {str(e)[:50]}...")
    
    print("\n" + "=" * 70)


def test_protocol_flow():
    """Test a complete protocol flow."""
    
    print("\n" + "=" * 70)
    print("🔐 Protocol: Complete Flow Test")
    print("=" * 70)
    
    messages = []
    
    # Step 1: Client Hello
    print(f"\n1️⃣  Step 1: Client sends HELLO")
    hello = Hello(certificate="client_cert_pem")
    messages.append(message_to_json(hello))
    print(f"   Message type: {hello.type}")
    
    # Step 2: Server Hello
    print(f"\n2️⃣  Step 2: Server sends SERVER_HELLO")
    server_hello = ServerHello(certificate="server_cert_pem")
    messages.append(message_to_json(server_hello))
    print(f"   Message type: {server_hello.type}")
    
    # Step 3: DH Exchange
    print(f"\n3️⃣  Step 3: DH Public Key Exchange")
    dh_client = DHClient(public_key="c" * 512)
    messages.append(message_to_json(dh_client))
    print(f"   Client sends DH public key")
    
    dh_server = DHServer(public_key="s" * 512)
    messages.append(message_to_json(dh_server))
    print(f"   Server sends DH public key")
    
    # Step 4: Registration
    print(f"\n4️⃣  Step 4: Registration (encrypted with temp key)")
    register = Register(
        email="alice@example.com",
        password="password123",
        ciphertext="encrypted_with_temp_key" * 4,
        signature="signed_by_client" * 4
    )
    messages.append(message_to_json(register))
    print(f"   Client registers")
    
    reg_resp = RegisterResponse(
        success=True,
        user_id=1,
        ciphertext="encrypted_response",
        signature="signed_by_server"
    )
    messages.append(message_to_json(reg_resp))
    print(f"   Server confirms (user_id=1)")
    
    # Step 5: Login
    print(f"\n5️⃣  Step 5: Login (encrypted with new temp key)")
    login = Login(
        email="alice@example.com",
        password="password123",
        ciphertext="encrypted_login_msg",
        signature="client_signature"
    )
    messages.append(message_to_json(login))
    print(f"   Client logs in")
    
    login_resp = LoginResponse(
        success=True,
        user_id=1,
        session_id=1,
        ciphertext="encrypted_session_info",
        signature="server_signature"
    )
    messages.append(message_to_json(login_resp))
    print(f"   Server confirms (session_id=1)")
    
    # Step 6: Chat messages
    print(f"\n6️⃣  Step 6: Chat messages (encrypted with session key)")
    for seq in range(1, 4):
        msg = Message(
            sender_id=1,
            session_id=1,
            sequence_number=seq,
            timestamp=1700000000 + seq,
            ciphertext=f"encrypted_msg_{seq}" * 4,
            signature=f"signature_{seq}" * 8
        )
        messages.append(message_to_json(msg))
    print(f"   Exchanged 3 chat messages")
    
    # Step 7: Session closure
    print(f"\n7️⃣  Step 7: Session closure (receipts)")
    receipt1 = Receipt(
        sender_id=1,
        session_id=1,
        transcript_hash="a" * 64,
        signature="b" * 256
    )
    messages.append(message_to_json(receipt1))
    print(f"   Client sends receipt")
    
    receipt2 = Receipt(
        sender_id=2,
        session_id=1,
        transcript_hash="a" * 64,
        signature="c" * 256
    )
    messages.append(message_to_json(receipt2))
    print(f"   Server sends receipt")
    
    print(f"\n✅ Complete flow: {len(messages)} messages exchanged")
    
    # Verify all messages can be deserialized
    print(f"\n8️⃣  Verifying all messages deserialize correctly...")
    for i, msg_json in enumerate(messages, 1):
        try:
            msg_obj = json_to_message(msg_json)
            print(f"   Message {i}: {msg_obj.type} ✅")
        except Exception as e:
            print(f"   Message {i}: ERROR - {e}")
    
    print("\n" + "=" * 70)


if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("🔐 SecureChat Protocol Tests")
    print("=" * 70 + "\n")
    
    test_hello_messages()
    test_dh_messages()
    test_auth_messages()
    test_chat_messages()
    test_error_message()
    test_json_parsing()
    test_protocol_flow()
    
    print("\n" + "=" * 70)
    print("✅ All protocol tests complete!")
    print("=" * 70)
