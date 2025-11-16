"""
Script to generate a new RSA key pair and an X.509 certificate
signed by our existing Root CA.

This will be used to create certificates for the server and client.
"""

import argparse
import datetime
import pathlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Define the certs directory
CERT_DIR = pathlib.Path(__file__).parent.parent / "certs"

# Paths to the existing Root CA files
CA_KEY_FILE = CERT_DIR / "ca_private_key.pem"
CA_CERT_FILE = CERT_DIR / "ca_cert.pem"


def load_ca_files():
    """Loads the CA's private key and certificate from disk."""
    
    # Load CA private key
    with open(CA_KEY_FILE, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
        
    # Load CA certificate
    with open(CA_CERT_FILE, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
        
    return ca_private_key, ca_cert


def generate_certificate(common_name: str, output_base_path: str, validity_days: int = 365):
    """
    Generates a new private key and a certificate signed by the CA.
    """
    
    # 1. Load the CA's key and certificate
    print(f"Loading CA from {CA_CERT_FILE}...")
    try:
        ca_private_key, ca_cert = load_ca_files()
    except FileNotFoundError:
        print(f"Error: CA files not found. Please run 'gen_ca.py' first.")
        return

    # 2. Generate a new RSA private key for this entity (server or client)
    print(f"Generating new 2048-bit RSA private key for '{common_name}'...")
    new_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 3. Define the "Subject" of the new certificate
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name), # e.g., "server.local"
    ])

    # 4. Build the certificate
    # The Issuer is the Subject of the CA certificate
    builder = x509.CertificateBuilder().subject_name(
        subject_name
    ).issuer_name(
        ca_cert.subject # Set the issuer to our CA
    ).public_key(
        new_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days)
    )

    # 5. Add X.509 Extensions
    # `CA:FALSE` means this is an "end-entity" cert, not a CA.
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    
    # Add Authority Key Identifier (AKI) to link back to the CA
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False
    )
    
    # Add Subject Alternative Name (SAN) - good practice
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    )

    # 6. Sign the certificate with the CA's private key
    print(f"Signing certificate with CA key...")
    new_certificate = builder.sign(
        private_key=ca_private_key, # Sign with the CA's key
        algorithm=hashes.SHA256()
    )

    # 7. Save the new private key and certificate
    
    # Ensure the 'certs' directory exists
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    
    key_path = f"{output_base_path}_private_key.pem"
    cert_path = f"{output_base_path}_cert.pem"

    # Save the new private key
    with open(key_path, "wb") as f:
        f.write(
            new_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print(f"Success: Entity private key saved to {key_path}")

    # Save the new certificate
    with open(cert_path, "wb") as f:
        f.write(
            new_certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            )
        )
    print(f"Success: Entity certificate saved to {cert_path}")


def main():
    """
    Parse arguments and run the certificate generation.
    """
    parser = argparse.ArgumentParser(description="Generate a new certificate signed by the Root CA.")
    parser.add_argument(
        "--cn",
        type=str,
        required=True,
        help="The Common Name (CN) for the new certificate (e.g., 'server.local')"
    )
    parser.add_argument(
        "--out",
        type=str,
        required=True,
        help="The output file base path (e.g., 'certs/server' -> certs/server_cert.pem)"
    )
    args = parser.parse_args()
    
    # Ensure the output path's directory exists
    output_path = pathlib.Path(args.out)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    generate_certificate(common_name=args.cn, output_base_path=args.out)


if __name__ == "__main__":
    main()