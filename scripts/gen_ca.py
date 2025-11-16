"""
Script to generate a Root Certificate Authority (CA).

Creates:
1.  A new RSA private key for the CA (ca_private_key.pem)
2.  A self-signed X.509 certificate (ca_cert.pem)

This certificate is the "root of trust" for the system.
"""

import argparse
import datetime
import pathlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Define output directory and file paths
CERT_DIR = pathlib.Path(__file__).parent.parent / "certs"
CA_KEY_FILE = CERT_DIR / "ca_private_key.pem"
CA_CERT_FILE = CERT_DIR / "ca_cert.pem"

def generate_ca(common_name: str, validity_days: int = 365 * 10):
    """
    Generates a new RSA private key and a self-signed CA certificate.
    """
    
    print(f"Generating new Root CA with Common Name: '{common_name}'")

    # 1. Generate a new RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # 2. Define the "Subject" of the certificate (who it is for)
    # For a self-signed root, Subject and Issuer are the same.
    subject_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat Org"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    issuer_name = subject_name # Self-signed

    # 3. Build the certificate
    builder = x509.CertificateBuilder().subject_name(
        subject_name
    ).issuer_name(
        issuer_name
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number() # Unique serial number
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc) # Valid from now
    ).not_valid_after(
        # Valid for specified number of days
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=validity_days)
    )

    # 4. Add X.509 Extensions
    # `CA:TRUE` means it can be used to sign other certificates.
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    
    # Add Subject Key Identifier (SKI) and Authority Key Identifier (AKI)
    # For a root CA, SKI and AKI are the same.
    ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
    builder = builder.add_extension(ski, critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(private_key.public_key()),
        critical=False
    )

    # 5. Sign the certificate with its own private key
    ca_certificate = builder.sign(
        private_key=private_key, 
        algorithm=hashes.SHA256()
    )

    # 6. Save the private key and certificate to files
    
    # Ensure the 'certs' directory exists
    CERT_DIR.mkdir(parents=True, exist_ok=True)

    # Save the private key (unencrypted for this assignment)
    with open(CA_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    print(f"Success: CA private key saved to {CA_KEY_FILE}")

    # Save the certificate
    with open(CA_CERT_FILE, "wb") as f:
        f.write(
            ca_certificate.public_bytes(
                encoding=serialization.Encoding.PEM
            )
        )
    print(f"Success: CA certificate saved to {CA_CERT_FILE}")


def main():
    """
    Parse arguments and run the CA generation.
    """
    parser = argparse.ArgumentParser(description="Generate a Root CA certificate and private key.")
    parser.add_argument(
        "--name",
        type=str,
        required=True,
        help="The Common Name (CN) for the Root CA (e.g., 'FAST-NU Root CA')"
    )
    args = parser.parse_args()
    
    generate_ca(common_name=args.name)


if __name__ == "__main__":
    main()