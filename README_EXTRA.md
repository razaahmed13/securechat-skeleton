# SecureChat — Quickstart & Implementation Notes

This companion file contains quickstart instructions, implementation status and integration notes for the local fork of the SecureChat project.

## ✅ Implementation status (local fork)

This repository contains a complete implementation (Commits 1–9) of the SecureChat assignment. Key points:

- Unit tests for crypto, PKI, storage and protocol are provided and passing locally.
- A TCP-based client/server pair implementing the 6-phase handshake (certificate exchange, DH auth, auth, DH session, messaging, receipts) is included.
- SQLite is used as the backing store (no external MySQL required).

See `PROGRESS.md` for a detailed commit-by-commit breakdown and next steps.

## Quickstart (Windows PowerShell)

1) Create and activate a virtual environment:

    # Create venv
    python -m venv .venv
    # Activate (PowerShell)
    .\.venv\Scripts\Activate.ps1
    pip install -r requirements.txt

2) Initialize database and generate certs (scripts provided):

    python scripts/init_db.py
    python scripts/gen_ca.py --name "FAST-NU Root CA"
    python scripts/gen_cert.py --cn server.local --out certs/server
    python scripts/gen_cert.py --cn client.local --out certs/client

3) Run the server (PowerShell):

    python test_integration.py --mode server

4) In a second terminal, run a client:

    python test_integration.py --mode client --email alice@example.com --password alice123

5) (Optional) Run unit tests individually:

    python test_protocol.py
    python test_aes.py
    python test_dh.py
    python test_sign.py
    python test_pki.py
    python test_db.py

## Integration notes

- The server and client use plain TCP sockets; all cryptographic operations are performed at the application layer as required by the assignment.
- The AES mode used is ECB for simplicity (assignment constraint); do not reuse this mode in production.
- For packet captures, look for the certificate exchange (plaintext PEM) in the initial HELLO messages and encrypted payloads thereafter.

## Next steps

- Run integration tests: start the server, connect two clients and exchange messages.
- Capture network traffic in Wireshark and verify only certificates are in plaintext.
- Perform tamper and replay tests to demonstrate signature and replay protection.
