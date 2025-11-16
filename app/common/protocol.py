"""
Pydantic models for all messages in the secure chat protocol.

- Defines the structure for:
  hello, server_hello, register, login, dh_client, dh_server, msg, receipt
- Provides helper functions to serialize (model -> bytes)
  and parse (bytes -> model).
"""

import json
from pydantic import BaseModel
from typing import Literal, Union, get_args

# --- Control Plane Models (Section 1.1) ---

class HelloModel(BaseModel):
    """
    Client -> Server: First message.
    { "type": "hello", "client_cert":"...PEM...", "nonce": base64 }
    """
    type: Literal["hello"] = "hello"
    client_cert: str  # Base64 encoded PEM string
    nonce: str        # Base64 encoded bytes

class ServerHelloModel(BaseModel):
    """
    Server -> Client: Response to "hello".
    { "type": "server_hello", "server_cert":"...PEM...", "nonce": base64 }
    """
    type: Literal["server_hello"] = "server_hello"
    server_cert: str  # Base64 encoded PEM string
    nonce: str        # Base64 encoded bytes

class RegisterModel(BaseModel):
    """
    Client -> Server: Encrypted registration request.
    { "type": "register", "email":"", "username": "", "pwd": ..., "salt": ... }
    """
    type: Literal["register"] = "register"
    email: str
    username: str
    pwd: str          # Base64 encoded (AES encrypted) hash
    salt: str         # Base64 encoded (AES encrypted) salt

class LoginModel(BaseModel):
    """
    Client -> Server: Encrypted login request.
    { "type": "login", "email":"", "pwd": ..., "nonce": ... }
    """
    type: Literal["login"] = "login"
    email: str
    pwd: str          # Base64 encoded (AES encrypted) hash
    nonce: str        # Base64 encoded (AES encrypted) nonce

# --- Key Agreement Models (Section 1.2) ---

class DhClientModel(BaseModel):
    """
    Client -> Server: Chat session key agreement init.
    { "type": "dh_client", "g": int, "p": int, "A": int }
    """
    type: Literal["dh_client"] = "dh_client"
    g: int
    p: int
    A: int            # Public value A

class DhServerModel(BaseModel):
    """
    Server -> Client: Chat session key agreement response.
    { "type": "dh_server", "B": int }
    """
    type: Literal["dh_server"] = "dh_server"
    B: int            # Public value B

# --- Data Plane Model (Section 1.3) ---

class MsgModel(BaseModel):
    """
    Client <-> Server: Encrypted chat message.
    { "type": "msg", "seqno": n, "ts": unix_ms, "ct": base64, "sig": ... }
    """
    type: Literal["msg"] = "msg"
    seqno: int
    ts: int           # Unix timestamp in ms
    ct: str           # Base64 encoded ciphertext
    sig: str          # Base64 encoded signature

# --- Non-Repudiation Model (Section 1.4) ---

class ReceiptModel(BaseModel):
    """
    Client <-> Server: Final signed receipt of the transcript.
    { "type": "receipt", "peer":"...", "first_seq":..., "last_seq":...., ... }
    """
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"]
    first_seq: int
    last_seq: int
    transcript_sha256: str  # Hex string
    sig: str                # Base64 encoded signature

# --- Generic Success/Error Models (Helper) ---

class ErrorModel(BaseModel):
    """A generic error message."""
    type: Literal["error"] = "error"
    code: str   # e.g., "BAD_CERT", "SIG_FAIL", "REPLAY"
    message: str

class SuccessModel(BaseModel):
    """A generic success/ack message (e.g., for login)."""
    type: Literal["success"] = "success"
    message: str = "Operation successful"

# --- Parsing and Serialization ---

# A Union of all possible message types
AnyMessage = Union[
    HelloModel,
    ServerHelloModel,
    RegisterModel,
    LoginModel,
    DhClientModel,
    DhServerModel,
    MsgModel,
    ReceiptModel,
    ErrorModel,
    SuccessModel
]

# A dictionary to map "type" strings to their Pydantic model class
MESSAGE_TYPE_MAP = {
    model.model_fields["type"].default: model for model in get_args(AnyMessage)
}

def parse_message(data: bytes) -> AnyMessage:
    """
    Parses a raw bytestring from the network into a specific
    Pydantic message model.
    """
    try:
        # 1. Decode bytes to UTF-8 string
        json_str = data.decode('utf-8')
        # 2. Parse string into a Python dictionary
        msg_dict = json.loads(json_str)
    except Exception:
        raise ValueError(f"Invalid JSON data: {data.decode('utf-8', errors='ignore')}")

    # 3. Get the 'type' field from the dictionary
    msg_type = msg_dict.get("type")
    if not msg_type:
        raise ValueError("Message has no 'type' field.")

    # 4. Find the correct Pydantic model from our map
    model_class = MESSAGE_TYPE_MAP.get(msg_type)
    if not model_class:
        raise ValueError(f"Unknown message type: '{msg_type}'")

    # 5. Validate the dictionary against the model
    try:
        return model_class.model_validate(msg_dict)
    except Exception as e:
        raise ValueError(f"Message validation failed for type '{msg_type}': {e}")

def serialize_message(model: BaseModel) -> bytes:
    """
    Serializes a Pydantic message model into a bytestring
    for sending over the network.
    """
    # 1. Convert Pydantic model to a JSON string
    json_str = model.model_dump_json()
    # 2. Encode the string as UTF-8 bytes
    return json_str.encode('utf-8')