#!/usr/bin/env python3
"""Test X.509 certificate validation implementation."""

from app.crypto.pki import CertificateValidator, validate_certificate, validate_peer_certificate
from pathlib import Path


def test_load_certificates():
    """Test loading certificates."""
    
    print("=" * 70)
    print("🔐 Certificate Loading Test")
    print("=" * 70)
    
    certs_dir = Path('certs')
    
    # Load CA
    print(f"\n1️⃣  Loading CA certificate...")
    try:
        ca_cert = CertificateValidator.load_certificate(certs_dir / 'ca.crt')
        print(f"   ✅ CA certificate loaded")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return
    
    # Load server cert
    print(f"\n2️⃣  Loading server certificate...")
    try:
        server_cert = CertificateValidator.load_certificate(certs_dir / 'server.crt')
        print(f"   ✅ Server certificate loaded")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return
    
    # Load client cert
    print(f"\n3️⃣  Loading client certificate...")
    try:
        client_cert = CertificateValidator.load_certificate(certs_dir / 'client.crt')
        print(f"   ✅ Client certificate loaded")
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return
    
    print("\n" + "=" * 70)
    return ca_cert, server_cert, client_cert


def test_certificate_validity(certs):
    """Test certificate validity checks."""
    
    ca_cert, server_cert, client_cert = certs
    
    print("\n" + "=" * 70)
    print("🔐 Certificate Validity Test")
    print("=" * 70)
    
    # Check CA validity
    print(f"\n1️⃣  Checking CA certificate validity...")
    is_valid, msg = CertificateValidator.is_valid_now(ca_cert)
    print(f"   CA valid now: {is_valid}")
    print(f"   Message: {msg}")
    
    # Check server validity
    print(f"\n2️⃣  Checking server certificate validity...")
    is_valid, msg = CertificateValidator.is_valid_now(server_cert)
    print(f"   Server valid now: {is_valid}")
    print(f"   Message: {msg}")
    
    # Check client validity
    print(f"\n3️⃣  Checking client certificate validity...")
    is_valid, msg = CertificateValidator.is_valid_now(client_cert)
    print(f"   Client valid now: {is_valid}")
    print(f"   Message: {msg}")
    
    print("\n" + "=" * 70)


def test_ca_self_signed(certs):
    """Test CA self-signed verification."""
    
    ca_cert, _, _ = certs
    
    print("\n" + "=" * 70)
    print("🔐 CA Self-Signed Verification Test")
    print("=" * 70)
    
    print(f"\n1️⃣  Verifying CA is self-signed...")
    is_valid, msg = CertificateValidator.verify_self_signed(ca_cert)
    
    if is_valid:
        print(f"   ✅ CA is self-signed")
    else:
        print(f"   ❌ CA verification failed: {msg}")
    
    print(f"   Message: {msg}")
    print("\n" + "=" * 70)


def test_certificate_signatures(certs):
    """Test certificate signature verification."""
    
    ca_cert, server_cert, client_cert = certs
    
    print("\n" + "=" * 70)
    print("🔐 Certificate Signature Verification Test")
    print("=" * 70)
    
    # Verify server cert signed by CA
    print(f"\n1️⃣  Verifying server certificate signed by CA...")
    is_valid, msg = CertificateValidator.verify_signature(server_cert, ca_cert)
    
    if is_valid:
        print(f"   ✅ Server certificate signed by CA")
    else:
        print(f"   ❌ Verification failed: {msg}")
    
    # Verify client cert signed by CA
    print(f"\n2️⃣  Verifying client certificate signed by CA...")
    is_valid, msg = CertificateValidator.verify_signature(client_cert, ca_cert)
    
    if is_valid:
        print(f"   ✅ Client certificate signed by CA")
    else:
        print(f"   ❌ Verification failed: {msg}")
    
    print("\n" + "=" * 70)


def test_certificate_chain(certs):
    """Test full certificate chain validation."""
    
    ca_cert, server_cert, client_cert = certs
    
    print("\n" + "=" * 70)
    print("🔐 Certificate Chain Validation Test")
    print("=" * 70)
    
    # Verify server cert chain
    print(f"\n1️⃣  Verifying server certificate chain...")
    is_valid, msg = CertificateValidator.verify_chain(server_cert, ca_cert)
    
    if is_valid:
        print(f"   ✅ Server certificate chain valid")
    else:
        print(f"   ❌ Chain validation failed")
    
    print(f"   Message: {msg}")
    
    # Verify client cert chain
    print(f"\n2️⃣  Verifying client certificate chain...")
    is_valid, msg = CertificateValidator.verify_chain(client_cert, ca_cert)
    
    if is_valid:
        print(f"   ✅ Client certificate chain valid")
    else:
        print(f"   ❌ Chain validation failed")
    
    print(f"   Message: {msg}")
    
    print("\n" + "=" * 70)


def test_certificate_information(certs):
    """Test certificate information extraction."""
    
    ca_cert, server_cert, client_cert = certs
    
    print("\n" + "=" * 70)
    print("🔐 Certificate Information Extraction Test")
    print("=" * 70)
    
    # CA info
    print(f"\n1️⃣  CA Certificate Information:")
    ca_info = CertificateValidator.get_certificate_info(ca_cert)
    print(f"   Subject: {ca_info['subject']}")
    print(f"   Issuer: {ca_info['issuer']}")
    print(f"   Serial: {ca_info['serial']}")
    print(f"   Valid From: {ca_info['valid_from']}")
    print(f"   Valid To: {ca_info['valid_to']}")
    print(f"   Key Size: {ca_info['key_size']} bits")
    print(f"   Signature Algorithm: {ca_info['signature_algorithm']}")
    print(f"   SANs: {ca_info['subject_alt_names']}")
    
    # Server info
    print(f"\n2️⃣  Server Certificate Information:")
    server_info = CertificateValidator.get_certificate_info(server_cert)
    print(f"   Subject: {server_info['subject']}")
    print(f"   Issuer: {server_info['issuer']}")
    print(f"   Serial: {server_info['serial']}")
    print(f"   Key Size: {server_info['key_size']} bits")
    print(f"   SANs: {server_info['subject_alt_names']}")
    
    # Client info
    print(f"\n3️⃣  Client Certificate Information:")
    client_info = CertificateValidator.get_certificate_info(client_cert)
    print(f"   Subject: {client_info['subject']}")
    print(f"   Issuer: {client_info['issuer']}")
    print(f"   Serial: {client_info['serial']}")
    print(f"   Key Size: {client_info['key_size']} bits")
    print(f"   SANs: {client_info['subject_alt_names']}")
    
    print("\n" + "=" * 70)


def test_convenience_functions():
    """Test convenience validation functions."""
    
    print("\n" + "=" * 70)
    print("🔐 Convenience Functions Test")
    print("=" * 70)
    
    certs_dir = Path('certs')
    
    # Validate server cert
    print(f"\n1️⃣  Validating server certificate...")
    is_valid, info = validate_certificate(
        certs_dir / 'server.crt',
        certs_dir / 'ca.crt'
    )
    
    print(f"   Valid: {is_valid}")
    print(f"   Message: {info['validation_message']}")
    print(f"   Subject: {info['subject']}")
    print(f"   Issuer: {info['issuer']}")
    
    # Validate client cert
    print(f"\n2️⃣  Validating client certificate...")
    is_valid, info = validate_certificate(
        certs_dir / 'client.crt',
        certs_dir / 'ca.crt'
    )
    
    print(f"   Valid: {is_valid}")
    print(f"   Message: {info['validation_message']}")
    print(f"   Subject: {info['subject']}")
    print(f"   Issuer: {info['issuer']}")
    
    # Validate with expected CN
    print(f"\n3️⃣  Validating server with expected CN...")
    is_valid, msg = validate_peer_certificate(
        certs_dir / 'server.crt',
        certs_dir / 'ca.crt',
        expected_cn='server'
    )
    
    print(f"   Valid: {is_valid}")
    print(f"   Message: {msg}")
    
    # Validate with wrong expected CN
    print(f"\n4️⃣  Validating server with wrong expected CN...")
    is_valid, msg = validate_peer_certificate(
        certs_dir / 'server.crt',
        certs_dir / 'ca.crt',
        expected_cn='wrong_name'
    )
    
    print(f"   Valid: {is_valid}")
    print(f"   Message: {msg}")
    
    print("\n" + "=" * 70)


if __name__ == '__main__':
    print("\n" + "=" * 70)
    print("🔐 X.509 Certificate Validation Tests")
    print("=" * 70 + "\n")
    
    certs = test_load_certificates()
    if certs:
        test_certificate_validity(certs)
        test_ca_self_signed(certs)
        test_certificate_signatures(certs)
        test_certificate_chain(certs)
        test_certificate_information(certs)
    
    test_convenience_functions()
    
    print("\n" + "=" * 70)
    print("✅ All certificate validation tests complete!")
    print("=" * 70)
