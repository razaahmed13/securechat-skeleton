"""
Secure Chat Server (app/server.py) [UPDATED]

Implements the server-side logic for the secure chat protocol.
- Listens for client connections.
- Handles PKI, DH exchanges, and authentication.
- Manages the secure chat session.
"""

import socket
import threading
import sys
import json
import os
from typing import Optional, Tuple
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization

# --- Import all our crypto and common modules ---
from app.crypto import pki, dh as dh_crypto, aes, sign
from app.common import protocol, utils
from app.storage.transcript import Transcript

# --- Database Class (Move to app/storage/db.py if you want) ---
import mysql.connector
from mysql.connector import errorcode
from dotenv import load_dotenv

# Load .env file for database credentials
load_dotenv()

class Database:
    """Handles all database operations for the server."""
    
    def __init__(self):
        self.db_config = {
            'host': os.getenv('MYSQL_HOST', '127.0.0.1'),
            'port': os.getenv('MYSQL_PORT', '3306'),
            'user': os.getenv('MYSQL_USER'),
            'password': os.getenv('MYSQL_PASSWORD'),
            'database': os.getenv('MYSQL_DATABASE')
        }
        
    def _get_connection(self):
        """Helper to get a new DB connection."""
        try:
            conn = mysql.connector.connect(**self.db_config)
            return conn
        except mysql.connector.Error as err:
            print(f"[DB Error] Connection failed: {err}")
            return None

    def register_user(self, email: str, username: str, pwd_hash_hex: str, salt_hex: str) -> bool:
        """Stores a new user in the database."""
        conn = self._get_connection()
        if not conn: return False
        
        try:
            cursor = conn.cursor()
            query = """
            INSERT INTO users (email, username, pwd_hash, salt)
            VALUES (%s, %s, %s, %s)
            """
            cursor.execute(query, (email, username, pwd_hash_hex, salt_hex))
            conn.commit()
            return True
        except mysql.connector.Error as err:
            print(f"[DB Error] Registration failed: {err}")
            return False
        finally:
            if conn: conn.close()

    def get_user_salt(self, email: str) -> Optional[bytes]:
        """Retrieves a user's raw salt bytes by email."""
        conn = self._get_connection()
        if not conn: return None
        
        try:
            cursor = conn.cursor()
            query = "SELECT salt FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            # The 'salt' column is VARBINARY, but connector might return hex str
            # Let's handle both
            if result:
                if isinstance(result[0], bytes):
                    return result[0]
                elif isinstance(result[0], str):
                    return bytes.fromhex(result[0])
            return None
        except mysql.connector.Error as err:
            print(f"[DB Error] Get salt failed: {err}")
            return None
        finally:
            if conn: conn.close()

    def check_login(self, email: str, password: str) -> Optional[str]:
        """
        [UPDATED] Checks login by hashing the provided password with the stored salt.
        Returns the username if successful, None otherwise.
        """
        conn = self._get_connection()
        if not conn: return None
        
        try:
            cursor = conn.cursor(dictionary=True) # Use dictionary cursor
            query = "SELECT username, pwd_hash, salt FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            result = cursor.fetchone()
            
            if result:
                stored_hash = result['pwd_hash']
                salt_bytes = result['salt'] # This should be raw bytes
                username = result['username']
                
                # Hash the provided password with the stored salt
                computed_hash = utils.sha256_hex(salt_bytes + password.encode())
                
                # Securely compare the hashes
                if computed_hash == stored_hash:
                    return username
            return None
        except mysql.connector.Error as err:
            print(f"[DB Error] Login check failed: {err}")
            return None
        finally:
            if conn: conn.close()

# --- Network Helper Functions ---

def send_bytes(conn: socket.socket, data: bytes):
    """Sends a raw bytestring with a 4-byte length prefix."""
    try:
        conn.sendall(len(data).to_bytes(4, 'big') + data)
    except Exception as e:
        print(f"[Network Error] Failed to send data: {e}")

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
        raise # Re-raise to be caught by handler

# --- Main Server Class ---

class Server:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.db = Database()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            print("Loading server identity...")
            self.ca_cert = pki.load_ca_cert()
            self.server_cert, self.server_key = pki.load_identity("certs/server")
            self.server_cn = pki.get_certificate_cn(self.server_cert)
            print(f"Server CN: {self.server_cn}")
        except Exception as e:
            print(f"Fatal: Could not load server identity. {e}")
            sys.exit(1)

    def run(self):
        self.sock.bind((self.host, self.port))
        self.sock.listen(1)
        print(f"Server listening on {self.host}:{self.port}...")

        while True:
            try:
                conn, addr = self.sock.accept()
                print(f"[+] New connection from {addr[0]}:{addr[1]}")
                client_thread = threading.Thread(
                    target=self.handle_client, 
                    args=(conn,), 
                    daemon=True
                )
                client_thread.start()
            except KeyboardInterrupt:
                print("\nShutting down server...")
                break
            except Exception as e:
                print(f"[Error] Accept failed: {e}")
        self.sock.close()

    def handle_client(self, conn: socket.socket):
        """Manages the full lifecycle of a single client connection."""
        client_cert = None
        client_cn = "unknown"
        k_auth = None
        k_chat = None
        transcript = None
        
        try:
            # 1. PKI Handshake
            client_cert = self.perform_pki_handshake(conn)
            if not client_cert:
                raise ValueError("PKI Handshake failed.")
            client_cn = pki.get_certificate_cn(client_cert)
            print(f"[{client_cn}] PKI Handshake successful.")

            # 2. Auth Key Exchange (DH Exchange #1)
            k_auth = self.perform_auth_key_exchange(conn)
            if not k_auth:
                raise ValueError("Auth DH Exchange failed.")
            print(f"[{client_cn}] Auth Key Exchange successful.")

            # 3. Authentication (Register/Login)
            username = self.perform_authentication(conn, k_auth)
            if not username:
                raise ValueError("Client authentication failed.")
            print(f"[{client_cn}] Client authenticated as '{username}'.")
            
            # 4. Chat Key Exchange (DH Exchange #2)
            k_chat = self.perform_chat_key_exchange(conn)
            if not k_chat:
                raise ValueError("Chat DH Exchange failed.")
            print(f"[{client_cn}] Chat Key Exchange successful.")
            
            # 5. Run Chat Session
            transcript = Transcript(peer_name="server", peer_cn=client_cn)
            self.run_chat_session(conn, client_cn, client_cert, k_chat, transcript)

        except (ValueError, protocol.json.JSONDecodeError) as e:
            print(f"[{client_cn}] Protocol Error: {e}")
            try:
                send_message(conn, protocol.ErrorModel(code="PROTOCOL_ERROR", message=str(e)))
            except: pass
        except Exception as e:
            print(f"[Error] Unhandled exception in client handler: {e}")
        finally:
            if transcript:
                transcript_hash, path = transcript.finalize()
                print(f"[{client_cn}] Transcript saved to {path} with hash {transcript_hash}")
                # TODO: Send final receipt
            
            print(f"[-] Connection from {client_cn} closed.")
            conn.close()

    def perform_pki_handshake(self, conn: socket.socket) -> Optional[x509.Certificate]:
        # 1. Receive Client Hello
        msg = recv_message(conn)
        if not isinstance(msg, protocol.HelloModel):
            raise ValueError("Expected 'hello' message.")
            
        # 2. Verify Client Certificate
        client_cert = utils.b64_str_to_cert(msg.client_cert)
        pki.verify_certificate(client_cert, self.ca_cert, "client.local") 
        
        # 3. Send Server Hello
        server_hello = protocol.ServerHelloModel(
            server_cert=utils.cert_to_b64_str(self.server_cert),
            nonce=utils.b64e(utils.generate_nonce())
        )
        send_message(conn, server_hello)
        return client_cert

    def _perform_dh_exchange(self, conn: socket.socket) -> Optional[bytes]:
        # 1. Receive Client's public value (A)
        msg = recv_message(conn)
        if not isinstance(msg, protocol.DhClientModel):
            raise ValueError("Expected 'dh_client' message.")
            
        # 2. Generate server keypair (a, B)
        server_priv_key, server_pub_val = dh_crypto.generate_dh_keypair()
        
        # 3. Compute shared secret (K_s)
        shared_secret = dh_crypto.compute_shared_secret(server_priv_key, msg.A)
        derived_key = dh_crypto.derive_aes_key(shared_secret)
        
        # 4. Send server's public value (B)
        send_message(conn, protocol.DhServerModel(B=server_pub_val))
        return derived_key

    def perform_auth_key_exchange(self, conn: socket.socket) -> Optional[bytes]:
        return self._perform_dh_exchange(conn)

    def perform_chat_key_exchange(self, conn: socket.socket) -> Optional[bytes]:
        return self._perform_dh_exchange(conn)

    def perform_authentication(self, conn: socket.socket, k_auth: bytes) -> Optional[str]:
        """[UPDATED] Handles the Register or Login message, encrypted with K_auth."""
        
        # 1. Receive the encrypted auth message
        encrypted_data = recv_bytes(conn)
        if not encrypted_data: return None
        
        # 2. Decrypt the payload
        try:
            decrypted_bytes = aes.decrypt(k_auth, encrypted_data)
            auth_msg = protocol.parse_message(decrypted_bytes)
        except Exception:
            raise ValueError("Failed to decrypt or parse auth message. Wrong K_auth.")
            
        # 3. Handle Register
        if isinstance(auth_msg, protocol.RegisterModel):
            print(f"Processing registration for {auth_msg.email}...")
            # Client sends b64(hex_hash) and b64(salt_bytes)
            pwd_hash_hex = utils.b64d(auth_msg.pwd).decode()
            salt_hex = utils.b64d(auth_msg.salt).hex() # Store as hex
            
            if self.db.register_user(auth_msg.email, auth_msg.username, pwd_hash_hex, salt_hex):
                send_message(conn, protocol.SuccessModel(message="Registration successful"))
                return auth_msg.username
            else:
                raise ValueError("Registration failed (username/email may be taken).")

        # 4. Handle Login
        elif isinstance(auth_msg, protocol.LoginModel):
            print(f"Processing login for {auth_msg.email}...")
            # Client sends b64(raw_password)
            password = utils.b64d(auth_msg.pwd).decode()
            
            # TODO: Verify nonce `auth_msg.nonce` to prevent replay
            
            # [UPDATED] check_login now takes password, fetches salt,
            # computes hash, and returns username on success.
            username = self.db.check_login(auth_msg.email, password)
            if username:
                send_message(conn, protocol.SuccessModel(message="Login successful"))
                return username
            else:
                raise ValueError("Login failed (Invalid email or password).")
        
        else:
            raise ValueError("Expected 'register' or 'login' message.")

    def run_chat_session(
        self,
        conn: socket.socket,
        client_cn: str,
        client_cert: x509.Certificate,
        k_chat: bytes,
        transcript: Transcript
    ):
        """Main chat loop. Server sends first, then client."""
        
        server_seq = 0
        client_seq = 0
        
        print(f"\n--- Chat session started with {client_cn} ---")
        print("Type your message and press Enter. Type '/quit' to end.")

        try:
            while True:
                # 1. Server's turn to send
                server_plaintext = input(f"({self.server_cn}) > ")
                
                if server_plaintext == "/quit":
                    # TODO: Send final receipt
                    break
                
                server_seq += 1
                ts = utils.now_ms()
                ct_bytes = aes.encrypt(k_chat, server_plaintext.encode())
                ct_b64 = utils.b64e(ct_bytes)
                
                hash_to_sign = utils.sha256_bytes(f"{server_seq}{ts}{ct_b64}".encode())
                sig_bytes = sign.sign_hash(self.server_key, hash_to_sign)
                sig_b64 = utils.b64e(sig_bytes)
                
                transcript.log_message(self.server_cn, server_seq, ts, ct_b64, sig_b64)
                
                send_message(conn, protocol.MsgModel(
                    seqno=server_seq, ts=ts, ct=ct_b64, sig=sig_b64
                ))

                # 2. Client's turn to receive
                print(f"Waiting for {client_cn}...")
                client_msg = recv_message(conn)
                if not client_msg:
                    print("Client disconnected.")
                    break
                    
                if not isinstance(client_msg, protocol.MsgModel):
                    raise ValueError("Received non-msg during chat.")
                
                if client_msg.seqno <= client_seq:
                    raise ValueError(f"REPLAY attack detected. Seq: {client_msg.seqno}")
                client_seq = client_msg.seqno
                
                hash_to_verify = utils.sha256_bytes(f"{client_msg.seqno}{client_msg.ts}{client_msg.ct}".encode())
                sig_to_verify = utils.b64d(client_msg.sig)
                
                if not sign.verify_signature(client_cert, hash_to_verify, sig_to_verify):
                    raise ValueError("SIGNATURE failure. Message tampered.")
                
                transcript.log_message(
                    client_cn, client_msg.seqno, client_msg.ts, client_msg.ct, client_msg.sig
                )
                
                client_plaintext_bytes = aes.decrypt(k_chat, utils.b64d(client_msg.ct))
                print(f"({client_cn}) > {client_plaintext_bytes.decode()}")

        except Exception as e:
            print(f"[Error] Chat loop failed: {e}")
            try:
                send_message(conn, protocol.ErrorModel(code="CHAT_ERROR", message=str(e)))
            except: pass

if __name__ == "__main__":
    server = Server(host="127.0.0.1", port=12345)
    try:
        server.run()
    except KeyboardInterrupt:
        print("Server shutting down.")