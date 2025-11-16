"""
Manages the append-only session transcript for non-repudiation.

- Creates a unique transcript file for each session.
- Appends formatted messages.
- Computes the final SHA-256 hash of the entire transcript.
"""

import hashlib
import pathlib
import datetime
from app.common.utils import now_ms

# Define the output directory for transcripts
TRANSCRIPT_DIR = pathlib.Path(__file__).parent.parent.parent / "transcripts"

class Transcript:
    """
    Handles logging all messages to a file and calculating the final
    transcript hash for the SessionReceipt.
    """
    
    def __init__(self, peer_name: str, peer_cn: str):
        """
        Initializes a new transcript file and a hash object.
        
        Args:
            peer_name: "client" or "server" (who this transcript belongs to)
            peer_cn: The CN of the *other* party (e.g., "server.local")
        """
        # Ensure the transcripts directory exists
        TRANSCRIPT_DIR.mkdir(parents=True, exist_ok=True)
        
        # Create a unique filename, e.g., "client_vs_server.local_1678886400.log"
        timestamp = now_ms()
        safe_cn = peer_cn.replace(".", "_") # Make filename safe
        self.filename = f"{peer_name}_vs_{safe_cn}_{timestamp}.log"
        self.filepath = TRANSCRIPT_DIR / self.filename
        
        # Initialize the SHA-256 hash object
        self.hash_obj = hashlib.sha256()
        
        # Open the file for writing (and keep it open)
        try:
            self.file_handle = open(self.filepath, "w", encoding="utf-8")
            print(f"[Transcript] Logging session to {self.filename}")
        except IOError as e:
            print(f"Error: Could not create transcript file at {self.filepath}: {e}")
            raise

    def log_message(
        self,
        sender_cn: str,
        seqno: int,
        ts: int,
        ct: str,
        sig: str
    ):
        """
        Appends a message to the transcript file and updates the hash.
        
        Args:
            sender_cn: The CN of the message sender (e.g., "client.local")
            seqno: Sequence number
            ts: Timestamp (ms)
            ct: Base64 ciphertext string
            sig: Base64 signature string
        """
        # Format as per Section 1.4: "seqno | ts | ct | sig | peer-cert-fingerprint"
        # We use the sender_cn as the fingerprint/identifier.
        log_line = f"{seqno}|{ts}|{ct}|{sig}|{sender_cn}\n"
        
        try:
            # 1. Append the log line to the file
            self.file_handle.write(log_line)
            
            # 2. Update the running hash with the bytes of this line
            self.hash_obj.update(log_line.encode('utf-8'))
            
        except IOError as e:
            print(f"Error: Could not write to transcript file: {e}")

    def finalize(self) -> tuple[str, str]:
        """
        Closes the file and returns the final transcript hash.
        
        Returns:
            A tuple of (final_hash_hex, transcript_filepath)
        """
        try:
            # 1. Close the file
            self.file_handle.close()
            
            # 2. Get the final hash
            final_hash_hex = self.hash_obj.hexdigest()
            
            print(f"[Transcript] Finalized. Hash: {final_hash_hex}")
            return final_hash_hex, str(self.filepath)
            
        except IOError as e:
            print(f"Error: Could not finalize transcript: {e}")
            return "ERROR_FINALIZING", str(self.filepath)