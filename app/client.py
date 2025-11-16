"""
Secure Chat Client (app/client.py)

Implements the client-side logic for the secure chat protocol.
- Connects to the server.
- Handles user input for registration or login.
- Manages the secure chat session.
"""

import socket
import sys
import getpass
from typing import Optional
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dh

# --- Import all our crypto and common modules ---
from app.crypto import pki, dh as dh_crypto, aes, sign
from app.common import protocol, utils
from app.storage.transcript import Transcript

# --- Network Helper Functions (Identical to server) ---

def send_bytes(conn: socket.socket, data: bytes):
    """Sends a raw bytestring with a 4-byte length prefix."""
    try:
        conn.sendall(len(data).to_bytes(4, 'big') + data)
    except Exception as e:
        print(f"[Network Error] Failed to send data: {e}")
        raise

def recv_bytes(conn: socket.socket) -> Optional[bytes]:
    """Receives a length-prefixed raw bytestring."""
    try:
        len_bytes = conn.recv(4)
        if not len_bytes: return None
        msg_len = int.from_bytes(len_bytes, 'big')
        
        data = b""
        while len(data) < msg_len:
            packet = conn.recv(msg_len - len(data))
            if not packet: return None
            data += packet
        return data
    except Exception as e:
        print(f"[Network Error] Failed to receive data: {e}")
        return None

def send_message(conn: socket.socket, msg_model: protocol.BaseModel):
    """Serializes a Pydantic model and sends it as bytes."""
    send_bytes(conn, protocol.serialize_message(msg_model))

def recv_message(conn: socket.socket) -> Optional[protocol.AnyMessage]:
    """Receives bytes and parses into a Pydantic model."""
    data = recv_bytes(conn)
    if data is None:
        return None
    try:
        return protocol.parse_message(data)
    except Exception as e:
        print(f"[Protocol Error] Failed to parse message: {e}")
        raise

# --- Main Client Class ---

class Client:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Load client identity and CA cert
        try:
            print("Loading client identity...")
            self.ca_cert = pki.load_ca_cert()
            self.client_cert, self.client_key = pki.load_identity("certs/client")
            self.client_cn = pki.get_certificate_cn(self.client_cert)
            print(f"Client CN: {self.client_cn}")
        except Exception as e:
            print(f"Fatal: Could not load client identity. {e}")
            sys.exit(1)

    def connect(self):
        """Connects to the server."""
        try:
            print(f"Connecting to {self.host}:{self.port}...")
            self.sock.connect((self.host, self.port))
            print("Connected.")
        except ConnectionRefusedError:
            print("Error: Connection refused. Is the server running?")
            sys.exit(1)
        except Exception as e:
            print(f"Error: Connection failed: {e}")
            sys.exit(1)

    def run(self):
        """Runs the full client protocol lifecycle."""
        server_cert = None
        server_cn = "unknown"
        k_auth = None
        k_chat = None
        transcript = None
        
        try:
            # 0. Connect
            self.connect()
            
            # 1. PKI Handshake
            server_cert = self.perform_pki_handshake()
            if not server_cert:
                raise ValueError("PKI Handshake failed.")
            server_cn = pki.get_certificate_cn(server_cert)
            print(f"PKI Handshake successful. Server is '{server_cn}'.")

            # 2. Auth Key Exchange (DH Exchange #1)
            k_auth = self.perform_auth_key_exchange()
            if not k_auth:
                raise ValueError("Auth DH Exchange failed.")
            print("Auth Key Exchange successful.")

            # 3. Authentication (Register/Login)
            if not self.perform_authentication(k_auth):
                raise ValueError("Authentication failed.")
            
            # 4. Chat Key Exchange (DH Exchange #2)
            k_chat = self.perform_chat_key_exchange()
            if not k_chat:
                raise ValueError("Chat DH Exchange failed.")
            print("Chat Key Exchange successful.")
            
            # 5. Run Chat Session
            transcript = Transcript(peer_name="client", peer_cn=server_cn)
            self.run_chat_session(k_chat, server_cn, server_cert, transcript)

        except (ValueError, protocol.json.JSONDecodeError) as e:
            print(f"Protocol Error: {e}")
        except Exception as e:
            print(f"Unhandled exception: {e}")
        finally:
            if transcript:
                transcript_hash, path = transcript.finalize()
                print(f"Transcript saved to {path} with hash {transcript_hash}")
                # TODO: Send final receipt
            
            print("Connection closed.")
            self.sock.close()

    def perform_pki_handshake(self) -> Optional[x509.Certificate]:
        """Handles the Client Hello / Server Hello certificate exchange."""
        # 1. Send Client Hello
        hello = protocol.HelloModel(
            client_cert=utils.cert_to_b64_str(self.client_cert),
            nonce=utils.b64e(utils.generate_nonce())
        )
        send_message(self.sock, hello)
        
        # 2. Receive Server Hello
        msg = recv_message(self.sock)
        if not isinstance(msg, protocol.ServerHelloModel):
            raise ValueError("Expected 'server_hello' message.")
            
        # 3. Verify Server Certificate
        server_cert = utils.b64_str_to_cert(msg.server_cert)
        # Note: "server.local" is the expected CN
        pki.verify_certificate(server_cert, self.ca_cert, "server.local") 
        
        return server_cert

    def _perform_dh_exchange(self) -> Optional[bytes]:
        """Helper for a single DH exchange. Returns the derived AES key."""
        # 1. Generate client keypair (a, A)
        client_priv_key, client_pub_val = dh_crypto.generate_dh_keypair()
        
        # 2. Send client's public value (A)
        # We use the hardcoded p, g from the dh_crypto module
        send_message(self.sock, protocol.DhClientModel(
            g=dh_crypto._g,
            p=dh_crypto._p,
            A=client_pub_val
        ))
        
        # 3. Receive server's public value (B)
        msg = recv_message(self.sock)
        if not isinstance(msg, protocol.DhServerModel):
            raise ValueError("Expected 'dh_server' message.")
            
        # 4. Compute shared secret (K_s)
        shared_secret = dh_crypto.compute_shared_secret(client_priv_key, msg.B)
        
        # 5. Derive AES key (K)
        return dh_crypto.derive_aes_key(shared_secret)

    def perform_auth_key_exchange(self) -> Optional[bytes]:
        return self._perform_dh_exchange(self)

    def perform_chat_key_exchange(self) -> Optional[bytes]:
        return self._perform_dh_exchange(self)

    def perform_authentication(self, k_auth: bytes) -> bool:
        """Handles user input for Register or Login."""
        
        action = input("Do you want to (r)egister or (l)ogin? ").strip().lower()
        
        if action == 'r':
            # --- Register ---
            email = input("Email: ").strip()
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ")
            
            # 1. Client generates salt and hashes password
            salt = utils.generate_nonce(16)
            pwd_hash = utils.sha256_hex(salt + password.encode())
            
            # 2. Create Register model
            model = protocol.RegisterModel(
                email=email,
                username=username,
                pwd=utils.b64e(pwd_hash.encode()), # b64(hex_hash)
                salt=utils.b64e(salt)             # b64(salt_bytes)
            )
            
        elif action == 'l':
            # --- Login ---
            email = input("Email: ").strip()
            password = getpass.getpass("Password: ")
            
            # 1. Create Login model
            # [UPDATED] We send the raw password, b64 encoded.
            # Server will handle hashing with the stored salt.
            model = protocol.LoginModel(
                email=email,
                pwd=utils.b64e(password.encode()),
                nonce=utils.b64e(utils.generate_nonce(16))
            )
        else:
            print("Invalid action.")
            return False
            
        # 3. Serialize, Encrypt, and Send the auth payload
        payload_bytes = protocol.serialize_message(model)
        encrypted_payload = aes.encrypt(k_auth, payload_bytes)
        send_bytes(self.sock, encrypted_payload)
        
        # 4. Wait for server's response
        response = recv_message(self.sock)
        
        if isinstance(response, protocol.SuccessModel):
            print(f"Success: {response.message}")
            return True
        elif isinstance(response, protocol.ErrorModel):
            print(f"Error: {response.message} ({response.code})")
            return False
        else:
            print(f"Unexpected response from server: {response}")
            return False

    def run_chat_session(
        self,
        k_chat: bytes,
        server_cn: str,
        server_cert: x509.Certificate,
        transcript: Transcript
    ):
        """Main chat loop. Receives first, then sends."""
        
        server_seq = 0
        client_seq = 0
        
        print(f"\n--- Chat session started with {server_cn} ---")
        print("Waiting for server... (Type '/quit' to end.)")
        
        try:
            while True:
                # 1. Client's turn to receive
                print(f"Waiting for {server_cn}...")
                server_msg = recv_message(self.sock)
                if not server_msg:
                    print("Server disconnected.")
                    break
                
                if not isinstance(server_msg, protocol.MsgModel):
                    raise ValueError("Received non-msg during chat.")
                
                # Verify sequence number
                if server_msg.seqno <= server_seq:
                    raise ValueError(f"REPLAY attack detected. Seq: {server_msg.seqno}")
                server_seq = server_msg.seqno
                
                # Verify signature
                hash_to_verify = utils.sha256_bytes(f"{server_msg.seqno}{server_msg.ts}{server_msg.ct}".encode())
                sig_to_verify = utils.b64d(server_msg.sig)
                
                if not sign.verify_signature(server_cert, hash_to_verify, sig_to_verify):
                    raise ValueError("SIGNATURE failure. Message tampered.")
                
                # Log to transcript
                transcript.log_message(
                    server_cn, server_msg.seqno, server_msg.ts, server_msg.ct, server_msg.sig
                )
                
                # Decrypt
                server_plaintext_bytes = aes.decrypt(k_chat, utils.b64d(server_msg.ct))
                print(f"({server_cn}) > {server_plaintext_bytes.decode()}")

                # 2. Client's turn to send
                client_plaintext = input(f"({self.client_cn}) > ")
                
                if client_plaintext == "/quit":
                    # TODO: Send final receipt
                    break
                
                client_seq += 1
                ts = utils.now_ms()
                ct_bytes = aes.encrypt(k_chat, client_plaintext.encode())
                ct_b64 = utils.b64e(ct_bytes)
                
                hash_to_sign = utils.sha256_bytes(f"{client_seq}{ts}{ct_b64}".encode())
                sig_bytes = sign.sign_hash(self.client_key, hash_to_sign)
                sig_b64 = utils.b64e(sig_bytes)
                
                transcript.log_message(self.client_cn, client_seq, ts, ct_b64, sig_b64)
                
                send_message(self.sock, protocol.MsgModel(
                    seqno=client_seq, ts=ts, ct=ct_b64, sig=sig_b64
                ))

        except Exception as e:
            print(f"[Error] Chat loop failed: {e}")
            try:
                send_message(self.sock, protocol.ErrorModel(code="CHAT_ERROR", message=str(e)))
            except: pass


if __name__ == "__main__":
    # Server host should be 127.0.0.1 (localhost)
    client = Client(host="127.0.0.1", port=12345)
    try:
        client.run()
    except KeyboardInterrupt:
        print("\nClient shutting down.")