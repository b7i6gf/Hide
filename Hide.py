#!/usr/bin/env python3
"""
Secure LSB Steganography with GUI
==================================

Modern GUI application for steganography with AES-256-GCM encryption
and Argon2id key derivation.

Author: b7i6gf + Claude Sonnet 4.6
Version: 1.0
"""

import os
import sys
import secrets
import subprocess
import threading
import queue
from typing import Optional, Tuple
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

import struct
import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# Reject decompression bombs - images above this pixel count are refused.
# 178,956,970 px ≈ ~170 MP (Pillow default); we lower it to a sane limit.
Image.MAX_IMAGE_PIXELS = 100_000_000   # 100 MP (~10 000 x 10 000 px)

# ---------------------------------------------------------------------------
# Payload format constants
# ---------------------------------------------------------------------------
# Binary payload layout (encrypted, version byte 0x01):
#   [0x01]  1 byte   – format version
#   [salt] 16 bytes  – Argon2id salt (random per operation)
#   [nonce] 12 bytes – AES-GCM nonce (random per operation)
#   [ct+tag] N+16 bytes – AES-256-GCM ciphertext + 128-bit auth tag
#
# The ciphertext decrypts to: magic_sequence + plaintext + end_delimiter
# Markers are therefore ALWAYS inside the ciphertext - never visible in raw data.
#
# Binary payload layout (unencrypted, version byte 0x00):
#   [0x00]  1 byte   – format version
#   [data]  N bytes  – magic_sequence + plaintext + end_delimiter in UTF-8
#
# All bytes are written directly as LSBs - no base64 encoding needed.

PAYLOAD_VERSION_ENC   = 0x01   # encrypted payload marker
PAYLOAD_VERSION_PLAIN = 0x00   # unencrypted payload marker
SALT_LEN  = 16   # 128-bit Argon2id salt
NONCE_LEN = 12   # 96-bit AES-GCM nonce (NIST recommended)
TAG_LEN   = 16   # 128-bit AES-GCM authentication tag
GCM_OVERHEAD = 1 + SALT_LEN + NONCE_LEN + TAG_LEN   # 45 bytes total
PLAIN_OVERHEAD = 1                                    # version byte only

# Argon2id parameters - "offline" hardening profile (RFC 9106 §4):
# 256 MB RAM + 4 iterations provides strong resistance against GPU brute-force.
# Key derivation takes ~1–2 s on typical desktop hardware - acceptable for a
# one-time unlock operation; not suitable for high-frequency use.
ARGON2_TIME_COST   = 4        # iterations (was 3)
ARGON2_MEMORY_COST = 262144   # 256 MB RAM (was 64 MB)
ARGON2_PARALLELISM = 4        # parallel lanes
ARGON2_KEY_LEN     = 32      # 256-bit output key for AES-256

# Binary stream layout in image LSBs:
#   [LEN_PREFIX: 4 bytes BE uint32] [PAYLOAD: LEN_PREFIX bytes]
# The length prefix lets extract_text() read exactly the right number of
# bytes so GCM never receives trailing garbage pixels.
LEN_PREFIX_BYTES = 4   # big-endian uint32 payload length header


class SteganographyError(Exception):
    """Custom exception for steganography errors."""
    pass


class SecureSteganography:
    """
    LSB steganography with AES-256-GCM authenticated encryption
    and Argon2id key derivation.

    Payload binary layout (encrypted):
        1 byte  version (0x01)
       16 bytes Argon2id salt
       12 bytes AES-GCM nonce
        N bytes AES-GCM ciphertext  (UTF-8 of magic+plaintext+end)
       16 bytes AES-GCM auth tag    (appended by AESGCM.encrypt)

    Markers live INSIDE the ciphertext - they are never visible in raw data.
    All error paths from decryption raise the same message to prevent oracles.
    """

    def __init__(self, password: Optional[str] = None,
                 magic_sequence: Optional[str] = None,
                 end_delimiter: Optional[str] = None):
        self.password = password
        self.magic_sequence = magic_sequence
        self.end_delimiter = end_delimiter

    # ------------------------------------------------------------------
    # Key derivation
    # ------------------------------------------------------------------

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derives a 256-bit AES key from password + salt using Argon2id.
        Uses ARGON2_TIME_COST / ARGON2_MEMORY_COST / ARGON2_PARALLELISM constants.
        Called by _build_payload() and _parse_payload().
        """
        try:
            kdf = Argon2id(
                salt=salt,
                length=ARGON2_KEY_LEN,
                iterations=ARGON2_TIME_COST,
                lanes=ARGON2_PARALLELISM,
                memory_cost=ARGON2_MEMORY_COST,
                ad=None,
                secret=None,
            )
            return kdf.derive(password.encode('utf-8'))
        except Exception as e:
            raise SteganographyError(f"Key derivation error: {e}")

    # ------------------------------------------------------------------
    # Payload assembly / disassembly
    # ------------------------------------------------------------------

    def _build_payload(self, plaintext: str) -> bytes:
        """
        Constructs the binary stream to be embedded in the image.

        Stream layout:
            4 bytes   big-endian uint32 - byte length of the payload block
            1 byte    version (0x01 encrypted / 0x00 plain)
           [encrypted path only]
           16 bytes   Argon2id salt
           12 bytes   AES-GCM nonce
            N bytes   AES-256-GCM ciphertext (UTF-8 of magic+plaintext+end)
           16 bytes   AES-GCM auth tag
           [plain path only]
            N bytes   UTF-8 of magic+plaintext+end

        Markers are INSIDE the ciphertext and never visible in raw bytes.
        Called by hide_text().
        """
        inner = (self.magic_sequence + plaintext + self.end_delimiter).encode('utf-8')

        if self.password:
            salt   = os.urandom(SALT_LEN)
            nonce  = os.urandom(NONCE_LEN)
            key    = self._derive_key(self.password, salt)
            ct_tag = AESGCM(key).encrypt(nonce, inner, None)
            payload = bytes([PAYLOAD_VERSION_ENC]) + salt + nonce + ct_tag
        else:
            payload = bytes([PAYLOAD_VERSION_PLAIN]) + inner

        return struct.pack('>I', len(payload)) + payload

    def _parse_payload(self, stream: bytes) -> str:
        """
        Reconstructs the plaintext from the full binary stream read from image LSBs.

        Reads the 4-byte length prefix first, then slices exactly that many bytes
        as the payload - trailing image bytes are discarded before any decryption.

        All failure paths (wrong password, GCM InvalidTag, wrong markers, bad version,
        truncated data, bad UTF-8) raise the same error message to prevent oracles.

        Called by extract_text().
        """
        _ERR = "Decryption failed - wrong password, wrong markers, or corrupted data."

        if len(stream) < LEN_PREFIX_BYTES:
            raise SteganographyError(_ERR)

        payload_len = struct.unpack('>I', stream[:LEN_PREFIX_BYTES])[0]

        # Reject obviously invalid lengths before any crypto work
        if payload_len == 0 or payload_len > len(stream) - LEN_PREFIX_BYTES:
            raise SteganographyError(_ERR)

        payload = stream[LEN_PREFIX_BYTES : LEN_PREFIX_BYTES + payload_len]
        version = payload[0]

        if version == PAYLOAD_VERSION_ENC:
            if not self.password:
                raise SteganographyError(_ERR)
            if len(payload) < 1 + SALT_LEN + NONCE_LEN + TAG_LEN:
                raise SteganographyError(_ERR)

            salt   = payload[1 : 1 + SALT_LEN]
            nonce  = payload[1 + SALT_LEN : 1 + SALT_LEN + NONCE_LEN]
            ct_tag = payload[1 + SALT_LEN + NONCE_LEN :]

            try:
                key   = self._derive_key(self.password, salt)
                inner = AESGCM(key).decrypt(nonce, ct_tag, None)
            except Exception:
                # Uniform error - GCM InvalidTag AND wrong-password-derived-key both land here
                raise SteganographyError(_ERR)

            try:
                inner_str = inner.decode('utf-8')
            except UnicodeDecodeError:
                raise SteganographyError(_ERR)

        elif version == PAYLOAD_VERSION_PLAIN:
            if self.password:
                # Caller expects encrypted data but payload is plain - uniform error
                raise SteganographyError(_ERR)
            try:
                inner_str = payload[1:].decode('utf-8')
            except UnicodeDecodeError:
                raise SteganographyError(_ERR)

        else:
            raise SteganographyError(_ERR)

        # Validate markers - same uniform error (no oracle distinguishing marker vs crypto failure)
        if not inner_str.startswith(self.magic_sequence):
            raise SteganographyError(_ERR)
        tail = inner_str[len(self.magic_sequence):]
        end_pos = tail.find(self.end_delimiter)
        if end_pos == -1:
            raise SteganographyError(_ERR)
        return tail[:end_pos]

    # ------------------------------------------------------------------
    # Binary ↔ bytes conversion
    # ------------------------------------------------------------------

    def _bytes_to_bits(self, data: bytes) -> np.ndarray:
        """
        Converts a byte sequence to a NumPy array of individual bits (uint8).
        Called by hide_text().
        """
        arr = np.frombuffer(data, dtype=np.uint8)
        # Unpack each byte into 8 bits, MSB first
        bits = np.unpackbits(arr)
        return bits

    def _bits_to_bytes(self, bits: np.ndarray, n_bytes: int) -> bytes:
        """
        Converts a NumPy bit array back to a byte string.
        Only the first n_bytes * 8 bits are used.
        Called by extract_text().
        """
        trimmed = bits[:n_bytes * 8]
        return np.packbits(trimmed).tobytes()

    # ------------------------------------------------------------------
    # Image helpers
    # ------------------------------------------------------------------

    def _validate_image(self, image_path: str) -> Image.Image:
        """
        Validates and loads an image, converts to RGB if needed.
        Called by hide_text(), extract_text(), and calculate_capacity().
        """
        if not os.path.exists(image_path):
            raise SteganographyError(f"Image file not found: {image_path}")
        try:
            img = Image.open(image_path)
            if img.mode != 'RGB':
                img = img.convert('RGB')
            return img
        except Exception as e:
            raise SteganographyError(f"Error loading image: {e}")

    # ------------------------------------------------------------------
    # Capacity
    # ------------------------------------------------------------------

    def calculate_capacity(self, image_path: str, encrypted: bool = False) -> int:
        """
        Returns the maximum plaintext character capacity of an image.

        Full binary stream overhead:
          - LEN_PREFIX_BYTES (4) always
          - encrypted: + 1 version + 16 salt + 12 nonce + 16 GCM tag = +45
          - plain:     + 1 version = +1
          - both:      + UTF-8 byte length of magic_sequence + end_delimiter

        Called by hide_text() and _update_char_count().
        """
        img = self._validate_image(image_path)
        img_array = np.array(img)

        available_bytes = (img_array.shape[0] * img_array.shape[1] * 3) // 8

        marker_bytes = 0
        if self.magic_sequence:
            marker_bytes += len(self.magic_sequence.encode('utf-8'))
        if self.end_delimiter:
            marker_bytes += len(self.end_delimiter.encode('utf-8'))

        crypto_overhead = GCM_OVERHEAD if encrypted else PLAIN_OVERHEAD
        total_overhead  = LEN_PREFIX_BYTES + crypto_overhead + marker_bytes
        return max(0, available_bytes - total_overhead)

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def hide_text(self, image_path: str, text: str, output_path: str,
                  progress_callback=None) -> dict:
        """
        Hides text in an image via LSB steganography.

        Uses NumPy vectorised bit operations for performance.
        Builds a binary payload via _build_payload(), embeds it bit by bit
        into the LSBs of the flattened RGB pixel array.
        Called by SteganographyGUI._hide_text() worker thread.
        """
        try:
            if not text.strip():
                raise SteganographyError("Text must not be empty.")

            img = self._validate_image(image_path)
            img_array = np.array(img)

            # Capacity check against encoded byte length (exact, not char estimate)
            max_chars = self.calculate_capacity(image_path, encrypted=bool(self.password))
            if len(text) > max_chars:
                raise SteganographyError(
                    f"Text too long! Maximum: {max_chars:,} characters, "
                    f"given: {len(text):,} characters"
                )

            payload_bytes = self._build_payload(text)
            payload_bits  = self._bytes_to_bits(payload_bytes)
            bit_count     = len(payload_bits)

            if bit_count > img_array.size:
                raise SteganographyError("Payload exceeds image capacity.")

            # Vectorised LSB embedding
            flat = img_array.flatten().astype(np.uint8)
            flat[:bit_count] = (flat[:bit_count] & np.uint8(0xFE)) | payload_bits
            img_array = flat.reshape(img_array.shape)

            if progress_callback:
                progress_callback(80)

            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)
            if not output_path.lower().endswith('.png'):
                output_path = os.path.splitext(output_path)[0] + '.png'

            Image.fromarray(img_array).save(output_path, 'PNG', optimize=False)

            if progress_callback:
                progress_callback(100)

            return {
                'success': True,
                'output_path': output_path,
                'text_length': len(text),
                'encrypted': bool(self.password),
                'capacity_used': f"{(len(payload_bytes) / (img_array.size // 8) * 100):.1f}%",
            }

        except SteganographyError:
            raise
        except Exception as e:
            raise SteganographyError(f"Unexpected error while hiding: {e}")

    def extract_text(self, image_path: str, progress_callback=None) -> dict:
        """
        Extracts hidden text from an image via LSB steganography.

        Reads the first LEN_PREFIX_BYTES (4) from the LSB stream to determine
        exact payload size, then reads only that many additional bytes - no
        trailing garbage reaches _parse_payload() or the GCM tag check.
        Called by SteganographyGUI._extract_text() and verify_integrity().
        """
        try:
            img = self._validate_image(image_path)
            img_array = np.array(img)

            flat     = img_array.flatten()
            lsb_bits = (flat & np.uint8(1)).astype(np.uint8)
            total_bits = len(lsb_bits)

            if total_bits < LEN_PREFIX_BYTES * 8:
                raise SteganographyError("Image too small to contain any payload.")

            if progress_callback:
                progress_callback(30)

            # Read the 4-byte length prefix first
            prefix_bytes = self._bits_to_bytes(lsb_bits, LEN_PREFIX_BYTES)
            payload_len  = struct.unpack('>I', prefix_bytes)[0]

            stream_len = LEN_PREFIX_BYTES + payload_len
            if stream_len * 8 > total_bits:
                raise SteganographyError(
                    "Decryption failed - wrong password, wrong markers, or corrupted data."
                )

            # Read exactly prefix + payload bytes - nothing more
            stream = self._bits_to_bytes(lsb_bits, stream_len)

            if progress_callback:
                progress_callback(70)

            final_text = self._parse_payload(stream)

            if progress_callback:
                progress_callback(100)

            return {
                'success': True,
                'text': final_text,
                'text_length': len(final_text),
                'encrypted': bool(self.password),
            }

        except SteganographyError:
            raise
        except Exception as e:
            raise SteganographyError(f"Error during extraction: {e}")

    def verify_integrity(self, image_path: str) -> bool:
        """
        Returns True if the image contains a valid hidden payload
        using the configured markers and password.
        Called by SteganographyGUI._verify_image().
        """
        try:
            result = self.extract_text(image_path)
            return result['success'] and len(result['text']) > 0
        except SteganographyError:
            return False

    @staticmethod
    def generate_random_password(length: int = 32) -> str:
        """
        Generates a cryptographically unbiased random password of the given length.
        Uses secrets.choice() for uniform distribution - no modulo bias.
        Called by SteganographyGUI._generate_key() to produce bundle credentials.
        """
        alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*'
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def generate_random_sequence(length: int = 12) -> str:
        """
        Generates a cryptographically unbiased alphanumeric sequence for magic/end markers.
        Uses secrets.choice() for uniform distribution - no modulo bias.
        Called by SteganographyGUI._generate_key() to produce bundle marker values.
        """
        alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    # ------------------------------------------------------------------
    # Key bundle - encrypted file format constants
    # ------------------------------------------------------------------
    # Encrypted bundle binary layout:
    #   4 bytes  magic header  b'SKBX'  (Secure Key Bundle eXcrypted)
    #   1 byte   version       0x01
    #  16 bytes  Argon2id salt (random per save)
    #  12 bytes  AES-GCM nonce (random per save)
    #   N bytes  AES-256-GCM ciphertext
    #  16 bytes  AES-GCM auth tag
    #
    # The magic header b'SKBX' is also used as GCM Additional Authenticated
    # Data (AAD) so that tampering with the header itself is detected.
    #
    # Plaintext inside ciphertext = UTF-8:
    #   [PW]>>password\n[mSEQ]>>magic\n[eSEQ]>>end\n

    _BUNDLE_MAGIC   = b'SKBX'
    _BUNDLE_VERSION = 0x01
    _B_SALT_LEN     = 16
    _B_NONCE_LEN    = 12
    _B_MIN_LEN      = 4 + 1 + 16 + 12 + 16   # magic + version + salt + nonce + tag

    @staticmethod
    def _bundle_derive_key(master_password: str, salt: bytes) -> bytes:
        """
        Derives a 256-bit AES key from master_password + salt using Argon2id.
        Uses the same KDF parameters as the stego encryption for consistency.
        Called by save_key_bundle() and load_key_bundle().
        """
        kdf = Argon2id(
            salt=salt,
            length=ARGON2_KEY_LEN,
            iterations=ARGON2_TIME_COST,
            lanes=ARGON2_PARALLELISM,
            memory_cost=ARGON2_MEMORY_COST,
            ad=None,
            secret=None,
        )
        return kdf.derive(master_password.encode('utf-8'))

    @staticmethod
    def save_key_bundle(filepath: str, password: str, magic_seq: str,
                        end_seq: str, master_password: str) -> None:
        """
        Encrypts and saves the key bundle to a binary file.

        The entire bundle content (stego password + both markers) is encrypted
        with AES-256-GCM using a key derived from master_password via Argon2id.
        The file contains NO plaintext - without the master password it is
        indistinguishable from random bytes.

        Called by SteganographyGUI._generate_key().
        """
        try:
            plaintext = (
                f"[PW]>>{password}\n"
                f"[mSEQ]>>{magic_seq}\n"
                f"[eSEQ]>>{end_seq}\n"
            ).encode('utf-8')

            salt   = os.urandom(SecureSteganography._B_SALT_LEN)
            nonce  = os.urandom(SecureSteganography._B_NONCE_LEN)
            key    = SecureSteganography._bundle_derive_key(master_password, salt)
            # Magic header used as AAD - tampering with it is detected by GCM
            ct_tag = AESGCM(key).encrypt(nonce, plaintext,
                                         SecureSteganography._BUNDLE_MAGIC)

            data = (
                SecureSteganography._BUNDLE_MAGIC
                + bytes([SecureSteganography._BUNDLE_VERSION])
                + salt + nonce + ct_tag
            )

            parent_dir = os.path.dirname(filepath) or '.'
            os.makedirs(parent_dir, exist_ok=True)
            with open(filepath, 'wb') as f:
                f.write(data)

            if sys.platform.startswith('win'):
                try:
                    subprocess.run(
                        ['attrib', '+h', filepath],
                        check=False, capture_output=True
                    )
                except Exception:
                    pass

        except SteganographyError:
            raise
        except Exception as e:
            raise SteganographyError(f"Error saving key bundle: {e}")

    @staticmethod
    def load_key_bundle(filepath: str, master_password: str) -> dict:
        """
        Loads and decrypts a key bundle file.

        Returns dict with keys: password, magic_seq, end_seq.
        Raises SteganographyError with a uniform message on any failure
        (wrong master password, tampered file, corrupt data) - no oracle.

        Called by SteganographyGUI._browse_key_file().
        """
        _ERR = "Invalid key bundle or wrong master password."

        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except Exception as e:
            raise SteganographyError(f"Error reading key file: {e}")

        if len(data) < 4:
            raise SteganographyError(_ERR)

        if data[:4] != SecureSteganography._BUNDLE_MAGIC:
            raise SteganographyError(
                "This file is not an encrypted key bundle.\n"
                "Please use a .key file generated by this application."
            )

        if len(data) < SecureSteganography._B_MIN_LEN:
            raise SteganographyError(_ERR)

        if data[4] != SecureSteganography._BUNDLE_VERSION:
            raise SteganographyError(_ERR)

        salt   = data[5 : 5 + SecureSteganography._B_SALT_LEN]
        nonce  = data[5 + SecureSteganography._B_SALT_LEN :
                      5 + SecureSteganography._B_SALT_LEN + SecureSteganography._B_NONCE_LEN]
        ct_tag = data[5 + SecureSteganography._B_SALT_LEN + SecureSteganography._B_NONCE_LEN :]

        try:
            key   = SecureSteganography._bundle_derive_key(master_password, salt)
            plain = AESGCM(key).decrypt(nonce, ct_tag,
                                        SecureSteganography._BUNDLE_MAGIC)
        except Exception:
            raise SteganographyError(_ERR)

        try:
            text = plain.decode('utf-8')
        except UnicodeDecodeError:
            raise SteganographyError(_ERR)

        result = {}
        prefixes = {
            '[PW]>>':   'password',
            '[mSEQ]>>': 'magic_seq',
            '[eSEQ]>>': 'end_seq',
        }
        for line in text.splitlines():
            for prefix, key_name in prefixes.items():
                if line.startswith(prefix):
                    value = line[len(prefix):]
                    if value:
                        result[key_name] = value
                    break

        if len(result) != 3:
            raise SteganographyError(_ERR)

        return result


def normalize_path(path_str: str) -> str:
    """
    Normalisiert Pfadangaben: entfernt Anführungszeichen, expandiert ~, macht absolut.
    Wird überall aufgerufen wo Entry-Felder Pfade liefern.
    """
    if not path_str:
        return ""
    path_str = path_str.strip()
    if ((path_str.startswith('"') and path_str.endswith('"')) or
            (path_str.startswith("'") and path_str.endswith("'"))):
        path_str = path_str[1:-1]
    try:
        return os.path.abspath(os.path.expanduser(path_str))
    except Exception:
        return path_str


def _ask_password(parent: tk.Tk, title: str, prompt: str) -> Optional[str]:
    """
    Shows a modal dialog with a masked password Entry.
    Returns the entered string, or None if the user cancelled.
    Called by SteganographyGUI._browse_key_file().
    """
    dialog = tk.Toplevel(parent)
    dialog.title(title)
    dialog.resizable(False, False)
    dialog.grab_set()

    result: list = [None]

    ttk.Label(dialog, text=prompt, justify=tk.LEFT).grid(
        row=0, column=0, columnspan=2, padx=16, pady=(14, 6), sticky=tk.W)

    var = tk.StringVar()
    entry = ttk.Entry(dialog, textvariable=var, show="*", width=32)
    entry.grid(row=1, column=0, columnspan=2, padx=16, pady=(0, 10))
    entry.focus_set()

    def on_ok(event=None):
        result[0] = var.get()
        dialog.destroy()

    def on_cancel(event=None):
        dialog.destroy()

    ttk.Button(dialog, text="OK",     command=on_ok).grid(
        row=2, column=0, padx=(16, 4), pady=(0, 14), sticky=tk.E)
    ttk.Button(dialog, text="Cancel", command=on_cancel).grid(
        row=2, column=1, padx=(4, 16), pady=(0, 14), sticky=tk.W)

    entry.bind("<Return>", on_ok)
    dialog.bind("<Escape>", on_cancel)

    # Centre over parent
    parent.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width()  - dialog.winfo_reqwidth())  // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - dialog.winfo_reqheight()) // 2
    dialog.geometry(f"+{x}+{y}")

    parent.wait_window(dialog)
    return result[0]


def _ask_password_confirm(parent: tk.Tk, title: str, prompt: str) -> Optional[str]:
    """
    Shows a modal dialog with a single masked password Entry for confirmation.
    Returns the entered string, or None if the user cancelled.
    Called by SteganographyGUI._generate_key() to confirm the master password.
    """
    return _ask_password(parent, title, prompt)


class SteganographyGUI:
    """
    Hauptklasse für die grafische Benutzeroberfläche.
    Kommuniziert mit Worker-Threads ausschließlich über self._gui_queue und root.after().
    """

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Hide - A Secure LSB Steganography Tool v1.0")
        self.root.geometry("820x700")
        self.root.minsize(640, 520)

        # Thread-sichere Queue für GUI-Updates aus Worker-Threads
        self._gui_queue: queue.Queue = queue.Queue()

        self._setup_styles()
        self._init_vars()
        self._setup_ui()

        # Queue-Polling starten
        self._poll_gui_queue()

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _setup_styles(self):
        """Configures ttk styles and fonts. Called by __init__."""
        self.default_font = ("Segoe UI", 10)
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TLabel', font=("Segoe UI", 10))
        self.style.configure('TButton', font=("Segoe UI", 10, "bold"), padding=(8, 4))
        self.style.configure('TEntry', font=("Segoe UI", 10), padding=4)
        self.style.configure('TCheckbutton', font=("Segoe UI", 10))
        self.style.configure('TFrame', padding=2)
        self.style.configure('TLabelframe.Label', font=("Segoe UI", 10, "bold"))
        self.style.configure('TNotebook.Tab', font=("Segoe UI", 10), padding=(10, 3))
        self.style.configure('Accent.TButton', font=("Segoe UI", 11, "bold"), padding=(14, 6))
        self.style.configure('RemoveKey.TButton', font=("Segoe UI", 10, "bold"), padding=(8, 4),
                             foreground='#8B0000')
        self.style.map('RemoveKey.TButton', foreground=[('disabled', 'gray'), ('active', '#6B0000')])
        self.style.configure('Green.Horizontal.TProgressbar', troughcolor='lightgray', background='green')
        self.style.configure('Yellow.Horizontal.TProgressbar', troughcolor='lightgray', background='orange')
        self.style.configure('Red.Horizontal.TProgressbar', troughcolor='lightgray', background='red')
        self.style.configure('DarkRed.Horizontal.TProgressbar', troughcolor='#FFD0B0', background='#B8500A')

    def _init_vars(self):
        """Initialises all tk.StringVars and tk.BooleanVars. Called by __init__."""
        # Hide Tab
        self.hide_image_var = tk.StringVar()
        self.hide_output_var = tk.StringVar()
        self.hide_magic_seq_var = tk.StringVar()
        self.hide_end_seq_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.show_password_var = tk.BooleanVar()
        self.char_count_var = tk.StringVar(value="0 characters")
        self.capacity_var = tk.StringVar(value="Select an image to see capacity")
        self.capacity_progress_var = tk.DoubleVar(value=0)

        # Extract Tab
        self.extract_image_var = tk.StringVar()
        self.extract_magic_seq_var = tk.StringVar()
        self.extract_end_seq_var = tk.StringVar()
        self.decrypt_password_var = tk.StringVar()
        self.show_decrypt_password_var = tk.BooleanVar()

        # Tools Tab
        self.cap_image_var = tk.StringVar()
        self.capacity_result_var = tk.StringVar()
        self.verify_image_var = tk.StringVar()
        self.verify_magic_seq_var = tk.StringVar()
        self.verify_end_seq_var = tk.StringVar()
        self.verify_password_var = tk.StringVar()
        self.verify_result_var = tk.StringVar()
        self.key_result_var = tk.StringVar()
        self.keygen_pw_var = tk.StringVar()
        self.keygen_magic_var = tk.StringVar()
        self.keygen_end_var = tk.StringVar()
        self.keygen_preview_var = tk.StringVar()
        self.keygen_master_var = tk.StringVar()
        self.keygen_master_show_var = tk.BooleanVar()

        # Internal storage for bundle credentials - never shown in the UI
        self._hide_real_password    = None
        self._hide_real_magic       = None
        self._hide_real_end         = None
        self._extract_real_password = None
        self._extract_real_magic    = None
        self._extract_real_end      = None
        self._verify_real_password  = None
        self._verify_real_magic     = None
        self._verify_real_end       = None

        self._hide_bundle_locked    = False
        self._extract_bundle_locked = False
        self._verify_bundle_locked  = False

        # Status
        self.status_var = tk.StringVar(value="Ready")
        self.progress_var = tk.DoubleVar()

    # ------------------------------------------------------------------
    # Thread-sichere GUI-Kommunikation
    # ------------------------------------------------------------------

    def _poll_gui_queue(self):
        """
        Verarbeitet ausstehende GUI-Aktionen aus Worker-Threads.
        Wird zyklisch alle 50ms vom Main-Thread via root.after() aufgerufen.
        """
        try:
            while True:
                action = self._gui_queue.get_nowait()
                action()
        except queue.Empty:
            pass
        self.root.after(50, self._poll_gui_queue)

    def _schedule(self, fn, *args, **kwargs):
        """
        Stellt eine GUI-Aktion in die Queue - sicher aus Worker-Threads aufrufbar.
        Wird von Worker-Threads aufgerufen um tkinter-Zugriffe zu delegieren.
        """
        self._gui_queue.put(lambda: fn(*args, **kwargs))

    # ------------------------------------------------------------------
    # UI-Aufbau
    # ------------------------------------------------------------------

    def _setup_ui(self):
        """Creates the full UI. Called by __init__."""
        main_frame = ttk.Frame(self.root, padding="6")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))

        self._create_hide_tab()
        self._create_extract_tab()
        self._create_tools_tab()
        self._create_status_area(main_frame)

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)

    def _create_hide_tab(self):
        """Creates the Hide Text tab. Called by _setup_ui()."""
        hide_frame = ttk.Frame(self.notebook, padding="8")
        self.notebook.add(hide_frame, text="Hide Text")

        # Image selection
        img_frame = ttk.LabelFrame(hide_frame, text="Source Image", padding="6")
        img_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 6))
        ttk.Entry(img_frame, textvariable=self.hide_image_var,
                  font=self.default_font).grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(img_frame, text="Browse",
                   command=self._browse_image_to_hide).grid(row=0, column=1)
        ttk.Label(img_frame, textvariable=self.capacity_var,
                  foreground="blue").grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=(3, 0))
        img_frame.columnconfigure(0, weight=1)

        # Output file - directly below source image
        output_frame = ttk.LabelFrame(hide_frame, text="Output File", padding="6")
        output_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 6))
        ttk.Entry(output_frame, textvariable=self.hide_output_var,
                  font=self.default_font).grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(output_frame, text="Save As",
                   command=self._browse_output_path).grid(row=0, column=1)
        output_frame.columnconfigure(0, weight=1)

        # Text input
        text_frame = ttk.LabelFrame(hide_frame, text="Text to Hide", padding="6")
        text_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 6))

        btn_bar = ttk.Frame(text_frame)
        btn_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 4))
        ttk.Button(btn_bar, text="Load File", command=self._load_text_file).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_bar, text="Paste", command=self._paste_from_clipboard).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_bar, text="Clear", command=self._clear_text).pack(side=tk.LEFT)

        self.hide_text_widget = scrolledtext.ScrolledText(
            text_frame, height=8, wrap=tk.WORD, font=("Segoe UI", 10))
        self.hide_text_widget.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.hide_text_widget.bind('<KeyRelease>', self._update_char_count)
        self.hide_text_widget.bind('<Button-1>', self._update_char_count)

        self.char_count_label = ttk.Label(text_frame, textvariable=self.char_count_var)
        self.char_count_label.grid(row=2, column=0, sticky=tk.W, pady=(3, 1))

        self.capacity_progress = ttk.Progressbar(
            text_frame, variable=self.capacity_progress_var,
            maximum=100, length=300, mode='determinate',
            style='Green.Horizontal.TProgressbar')

        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(1, weight=1)

        # Password & Markers
        opts_frame = ttk.LabelFrame(hide_frame, text="Password & Markers", padding="6")
        opts_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0, 6))

        # Row 0: password fields - always visible and active
        ttk.Label(opts_frame, text="Password:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.password_entry = ttk.Entry(opts_frame, textvariable=self.password_var,
                                        show="*", font=self.default_font)
        self.password_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 4))
        self.password_toggle_btn = ttk.Checkbutton(opts_frame, text="Show",
                                                   variable=self.show_password_var,
                                                   command=self._toggle_password_visibility)
        self.password_toggle_btn.grid(row=0, column=2, padx=(0, 0))
        self.hide_pw_clear_btn = ttk.Button(opts_frame, text="\u2715", width=2,
                                            command=lambda: self.password_var.set(""))
        self.hide_pw_clear_btn.grid(row=0, column=3, padx=(0, 8))
        self.key_file_btn = ttk.Button(opts_frame, text="Key File",
                                       command=lambda: self._browse_key_file('hide'))
        self.key_file_btn.grid(row=0, column=4, padx=(0, 4))
        self.hide_remove_key_btn = ttk.Button(opts_frame, text="Remove Key",
                                              command=lambda: self._clear_bundle('hide'),
                                              state="disabled", style="RemoveKey.TButton")
        self.hide_remove_key_btn.grid(row=0, column=5)

        # Divider
        ttk.Separator(opts_frame, orient='horizontal').grid(
            row=1, column=0, columnspan=6, sticky=(tk.W, tk.E), pady=5)

        # Row 2: start / end marker
        ttk.Label(opts_frame, text="Start Marker:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5))
        self.hide_magic_entry_frame = self._make_entry_with_clear(
            opts_frame, self.hide_magic_seq_var, on_clear=self._update_char_count)
        self.hide_magic_entry_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(0, 14))
        ttk.Label(opts_frame, text="End Marker:").grid(row=2, column=2, sticky=tk.W, padx=(0, 5))
        self.hide_end_entry_frame = self._make_entry_with_clear(
            opts_frame, self.hide_end_seq_var, on_clear=self._update_char_count)
        self.hide_end_entry_frame.grid(row=2, column=3, columnspan=3, sticky=(tk.W, tk.E))

        opts_frame.columnconfigure(1, weight=2)
        opts_frame.columnconfigure(3, weight=2)

        ttk.Button(hide_frame, text="Hide Text",
                   command=self._hide_text, style="Accent.TButton").grid(row=4, column=0, pady=7)

        hide_frame.columnconfigure(0, weight=1)
        hide_frame.rowconfigure(2, weight=1)

    def _create_extract_tab(self):
        """Creates the Extract Text tab. Called by _setup_ui()."""
        extract_frame = ttk.Frame(self.notebook, padding="8")
        self.notebook.add(extract_frame, text="Extract Text")

        # Image selection
        img_frame = ttk.LabelFrame(extract_frame, text="Image with Hidden Data", padding="6")
        img_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 6))
        ttk.Entry(img_frame, textvariable=self.extract_image_var,
                  font=self.default_font).grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(img_frame, text="Browse",
                   command=self._browse_image_to_extract).grid(row=0, column=1)
        img_frame.columnconfigure(0, weight=1)

        # Password & Markers
        opts_frame = ttk.LabelFrame(extract_frame, text="Password & Markers", padding="6")
        opts_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 6))

        # Row 0: password fields - always visible and active
        ttk.Label(opts_frame, text="Password:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.decrypt_password_entry = ttk.Entry(opts_frame, textvariable=self.decrypt_password_var,
                                                show="*", font=self.default_font)
        self.decrypt_password_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 4))
        self.decrypt_password_toggle_btn = ttk.Checkbutton(opts_frame, text="Show",
                                                           variable=self.show_decrypt_password_var,
                                                           command=self._toggle_decrypt_password_visibility)
        self.decrypt_password_toggle_btn.grid(row=0, column=2, padx=(0, 0))
        self.extract_pw_clear_btn = ttk.Button(opts_frame, text="\u2715", width=2,
                                               command=lambda: self.decrypt_password_var.set(""))
        self.extract_pw_clear_btn.grid(row=0, column=3, padx=(0, 8))
        self.decrypt_key_file_btn = ttk.Button(opts_frame, text="Key File",
                                               command=lambda: self._browse_key_file('extract'))
        self.decrypt_key_file_btn.grid(row=0, column=4, padx=(0, 4))
        self.extract_remove_key_btn = ttk.Button(opts_frame, text="Remove Key",
                                                 command=lambda: self._clear_bundle('extract'),
                                                 state="disabled", style="RemoveKey.TButton")
        self.extract_remove_key_btn.grid(row=0, column=5)

        # Divider
        ttk.Separator(opts_frame, orient='horizontal').grid(
            row=1, column=0, columnspan=6, sticky=(tk.W, tk.E), pady=5)

        # Row 2: start / end marker
        ttk.Label(opts_frame, text="Start Marker:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5))
        self.extract_magic_entry_frame = self._make_entry_with_clear(
            opts_frame, self.extract_magic_seq_var)
        self.extract_magic_entry_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), padx=(0, 14))
        ttk.Label(opts_frame, text="End Marker:").grid(row=2, column=2, sticky=tk.W, padx=(0, 5))
        self.extract_end_entry_frame = self._make_entry_with_clear(
            opts_frame, self.extract_end_seq_var)
        self.extract_end_entry_frame.grid(row=2, column=3, columnspan=3, sticky=(tk.W, tk.E))

        opts_frame.columnconfigure(1, weight=2)
        opts_frame.columnconfigure(3, weight=2)

        ttk.Button(extract_frame, text="Extract Text",
                   command=self._extract_text, style="Accent.TButton").grid(row=2, column=0, pady=7)

        # Result
        result_frame = ttk.LabelFrame(extract_frame, text="Extracted Text", padding="6")
        result_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 6))
        self.extract_text_widget = scrolledtext.ScrolledText(
            result_frame, height=10, wrap=tk.WORD, state="disabled", font=("Segoe UI", 10))
        self.extract_text_widget.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        btn_bar = ttk.Frame(result_frame)
        btn_bar.grid(row=1, column=0, pady=(4, 0))
        ttk.Button(btn_bar, text="Save to File",
                   command=self._save_extracted_text).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(btn_bar, text="Copy to Clipboard",
                   command=self._copy_extracted_to_clipboard).pack(side=tk.LEFT)

        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)
        extract_frame.columnconfigure(0, weight=1)
        extract_frame.rowconfigure(3, weight=1)

    def _create_tools_tab(self):
        """Creates the Tools tab (capacity, verify, key bundle). Called by _setup_ui()."""
        tools_frame = ttk.Frame(self.notebook, padding="8")
        self.notebook.add(tools_frame, text="Tools")

        # Check image capacity
        cap_frame = ttk.LabelFrame(tools_frame, text="Check Image Capacity", padding="6")
        cap_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 6))
        ttk.Entry(cap_frame, textvariable=self.cap_image_var,
                  font=self.default_font).grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(cap_frame, text="Browse",
                   command=self._browse_capacity_image).grid(row=0, column=1, padx=(0, 5))
        ttk.Button(cap_frame, text="Check",
                   command=self._check_capacity).grid(row=0, column=2)
        ttk.Label(cap_frame, textvariable=self.capacity_result_var,
                  foreground="blue").grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(5, 0))
        cap_frame.columnconfigure(0, weight=1)

        # Check for hidden data
        verify_frame = ttk.LabelFrame(tools_frame, text="Check for Hidden Data", padding="6")
        verify_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0, 6))

        # Row 0: image path + browse + check
        ttk.Label(verify_frame, text="Image:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        ttk.Entry(verify_frame, textvariable=self.verify_image_var,
                  font=self.default_font).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(verify_frame, text="Browse",
                   command=self._browse_verify_image).grid(row=0, column=2, padx=(0, 5))
        ttk.Button(verify_frame, text="Check",
                   command=self._verify_image).grid(row=0, column=3)

        # Row 1: password + Key File + Remove Key + status
        ttk.Label(verify_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.verify_password_entry_frame = self._make_entry_with_clear(
            verify_frame, self.verify_password_var, show="*")
        self.verify_password_entry_frame.grid(
            row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=(5, 0))
        self.verify_key_file_btn = ttk.Button(verify_frame, text="Key File",
                                              command=lambda: self._browse_key_file('verify'))
        self.verify_key_file_btn.grid(row=1, column=2, padx=(0, 5), pady=(5, 0))
        self.verify_remove_key_btn = ttk.Button(verify_frame, text="Remove Key",
                                                command=lambda: self._clear_bundle('verify'),
                                                state="disabled", style="RemoveKey.TButton")
        self.verify_remove_key_btn.grid(row=1, column=3, pady=(5, 0))
        self.verify_key_status_label = ttk.Label(verify_frame, text="Key loaded",
                                                 foreground="dark green")
        # Not gridded yet - shown only when a bundle is active

        # Row 2: start marker + end marker
        ttk.Label(verify_frame, text="Start Marker:").grid(row=2, column=0, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.verify_magic_entry_frame = self._make_entry_with_clear(
            verify_frame, self.verify_magic_seq_var)
        self.verify_magic_entry_frame.grid(
            row=2, column=1, sticky=(tk.W, tk.E), padx=(0, 5), pady=(5, 0))
        ttk.Label(verify_frame, text="End Marker:").grid(row=2, column=2, sticky=tk.W, padx=(0, 5), pady=(5, 0))
        self.verify_end_entry_frame = self._make_entry_with_clear(verify_frame, self.verify_end_seq_var)
        self.verify_end_entry_frame.grid(row=2, column=3, sticky=(tk.W, tk.E), pady=(5, 0))

        # Row 3: result label
        ttk.Label(verify_frame, textvariable=self.verify_result_var,
                  foreground="blue").grid(row=3, column=0, columnspan=4, sticky=tk.W, pady=(5, 0))

        verify_frame.columnconfigure(1, weight=2)
        verify_frame.columnconfigure(3, weight=1)

        # Generate key bundle - master password only, all values generated randomly
        key_frame = ttk.LabelFrame(tools_frame, text="Generate Key Bundle", padding="6")
        key_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 6))

        ttk.Label(key_frame,
                  text="Password and markers are generated randomly and stored encrypted.\n"
                       "You only need to set and remember the Master Password.",
                  foreground="gray", justify=tk.LEFT).grid(
                      row=0, column=0, columnspan=3, sticky=tk.W, pady=(0, 6))

        ttk.Label(key_frame, text="Master Password:").grid(row=1, column=0, sticky=tk.W, padx=(0, 5))
        self.keygen_master_entry = ttk.Entry(key_frame, textvariable=self.keygen_master_var,
                                             show="*", font=self.default_font)
        self.keygen_master_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), padx=(0, 4))
        ttk.Checkbutton(key_frame, text="Show",
                        variable=self.keygen_master_show_var,
                        command=lambda: self.keygen_master_entry.config(
                            show="" if self.keygen_master_show_var.get() else "*")
                        ).grid(row=1, column=2, padx=(0, 4))
        ttk.Button(key_frame, text="✕", width=2,
                   command=lambda: self.keygen_master_var.set("")).grid(row=1, column=3)
        ttk.Label(key_frame,
                  text="Required - encrypts the bundle file. Never stored anywhere!",
                  foreground="gray").grid(row=2, column=0, columnspan=4, sticky=tk.W, pady=(2, 0))

        ttk.Button(key_frame, text="Generate & Save",
                   command=self._generate_key).grid(row=3, column=0, columnspan=4,
                                                    sticky=tk.W, pady=(10, 0))
        ttk.Label(key_frame, textvariable=self.key_result_var,
                  foreground="green").grid(row=4, column=0, columnspan=4, sticky=tk.W, pady=(3, 0))

        key_frame.columnconfigure(1, weight=1)

        # About
        about_frame = ttk.LabelFrame(tools_frame, text="About", padding="6")
        about_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 6))
        about_text = (
            "Hide - A Secure LSB Steganography Tool \u2022  Version 1.0\n\n"
            "Steganography\n"
            "  \u2022  Least Significant Bit (LSB) embedding in RGB images\n"
            "  \u2022  Sequential pixel embedding - visually undetectable\n"
            "  \u2022  Supports PNG, JPEG, BMP, GIF, TIFF and more\n"
            "  \u2022  Output always saved as lossless PNG\n\n"
            "Cryptography\n"
            "  \u2022  AES-256-GCM authenticated encryption\n"
            "  \u2022  Argon2id key derivation (256 MB RAM \u2022 4 iterations \u2022 4 lanes)\n"
            "  \u2022  128-bit random salt + 96-bit random nonce per operation\n"
            "  \u2022  GCM auth tag validates integrity before any decryption\n"
            "  \u2022  Markers embedded inside ciphertext - never in plaintext\n"
            "  \u2022  Uniform error messages - no cryptographic oracle\n\n"
            "Key Bundle (.key files)\n"
            "  \u2022  Password + markers randomly generated, never typed\n"
            "  \u2022  Bundle encrypted with AES-256-GCM + Argon2id master key\n"
            "  \u2022  File header used as GCM AAD - tampering is detected\n\n"
            "Security Hardening\n"
            "  \u2022  Max image size: 100 MP (decompression bomb protection)\n"
            "  \u2022  Cryptographically unbiased random generation (secrets module)\n"
            "  \u2022  No shell injection (subprocess.run instead of os.system)\n\n"
            "Performance & Architecture\n"
            "  \u2022  NumPy-vectorised bit operations (100\u2013500\u00d7 vs pure Python)\n"
            "  \u2022  Thread-safe GUI - worker threads via queue, never freezes\n"
            "  \u2022  4-byte length prefix - exact payload read, no GCM padding waste\n\n"
            "Technologies\n"
            "  Python 3.14  \u2022  tkinter  \u2022 Pillow 12.0.0 \u2022 NumPy 2.4.2 \u2022 cryptography 46.0.5"
        )
        about_text_widget = scrolledtext.ScrolledText(
            about_frame, height=6, wrap=tk.WORD,
            font=("Segoe UI", 10), state="normal",
            relief=tk.FLAT, borderwidth=0
        )
        about_text_widget.insert("1.0", about_text)
        about_text_widget.config(state="disabled")
        about_text_widget.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        # Match background to the parent frame after rendering
        def _sync_bg():
            try:
                bg = about_frame.winfo_toplevel().cget("bg")
                about_text_widget.config(bg=bg)
            except Exception:
                pass
        about_frame.after(50, _sync_bg)
        about_frame.columnconfigure(0, weight=1)
        about_frame.rowconfigure(0, weight=1)

        tools_frame.columnconfigure(0, weight=1)
        tools_frame.rowconfigure(3, weight=1)

    def _make_entry_with_clear(self, parent, var: tk.StringVar, width: int = 25,
                               show: str = "", on_clear=None):
        """
        Creates a frame with an Entry and a small clear button.
        Returns the frame to be placed with .grid().
        on_clear: optional callback after clearing (e.g. recalculate capacity).
        Called from all tabs for non-path input fields.
        """
        frame = ttk.Frame(parent)
        entry_kwargs = dict(textvariable=var, font=self.default_font)
        if show:
            entry_kwargs['show'] = show
        entry = ttk.Entry(frame, **entry_kwargs)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        def do_clear():
            var.set("")
            if on_clear:
                on_clear()

        btn = ttk.Button(frame, text="✕", width=2, command=do_clear)
        btn.pack(side=tk.LEFT, padx=(3, 0))
        return frame

    def _create_status_area(self, parent):
        """Erstellt Fortschrittsbalken und Statuszeile. Wird von _setup_ui() aufgerufen."""
        status_frame = ttk.Frame(parent)
        status_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 10))
        ttk.Label(status_frame, textvariable=self.status_var).grid(row=0, column=1)
        status_frame.columnconfigure(0, weight=1)

    # ------------------------------------------------------------------
    # Browse-Helfer
    # ------------------------------------------------------------------

    def _browse_image_to_hide(self):
        """Öffnet Dateidialog für Quellbild (Hide-Tab). Wird vom Button aufgerufen."""
        filename = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[("All Images", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff"),
                       ("PNG", "*.png"), ("JPEG", "*.jpg *.jpeg"),
                       ("BMP", "*.bmp"), ("All Files", "*.*")])
        if filename:
            self.hide_image_var.set(filename)
            self._update_capacity_display()
            self._update_char_count()

    def _browse_image_to_extract(self):
        """Öffnet Dateidialog für Quellbild (Extract-Tab). Wird vom Button aufgerufen."""
        filename = filedialog.askopenfilename(
            title="Select Image with Hidden Data",
            filetypes=[("All Images", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff"),
                       ("PNG", "*.png"), ("All Files", "*.*")])
        if filename:
            self.extract_image_var.set(filename)

    def _browse_output_path(self):
        """Öffnet Speichern-Dialog für Ausgabedatei. Wird vom Button aufgerufen."""
        filename = filedialog.asksaveasfilename(
            title="Save Output File",
            defaultextension=".png",
            filetypes=[("PNG", "*.png"), ("All Files", "*.*")])
        if filename:
            self.hide_output_var.set(filename)

    def _browse_capacity_image(self):
        """Öffnet Dateidialog für Kapazitätsprüfung (Tools-Tab). Wird vom Button aufgerufen."""
        filename = filedialog.askopenfilename(
            title="Select Image for Capacity Check",
            filetypes=[("All Images", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff"),
                       ("All Files", "*.*")])
        if filename:
            self.cap_image_var.set(filename)

    def _browse_verify_image(self):
        """Öffnet Dateidialog für Verifikation (Tools-Tab). Wird vom Button aufgerufen."""
        filename = filedialog.askopenfilename(
            title="Select Image for Verification",
            filetypes=[("All Images", "*.png *.jpg *.jpeg *.bmp *.gif *.tiff"),
                       ("PNG", "*.png"), ("All Files", "*.*")])
        if filename:
            self.verify_image_var.set(filename)

    def _browse_key_file(self, context: str):
        """
        Opens file dialog, asks for master password, decrypts the bundle,
        stores credentials internally, and locks the relevant fields to readonly.
        Fields show a placeholder - actual values are never displayed.
        Called by the Key File buttons in Hide and Extract tabs.
        """
        filename = filedialog.askopenfilename(
            title="Select Encrypted Key Bundle",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
        if not filename:
            return

        master = _ask_password(
            self.root,
            title="Master Password",
            prompt=f"Master Password for\n{os.path.basename(filename)}:",
        )
        if master is None:
            return

        try:
            bundle = SecureSteganography.load_key_bundle(filename, master)
        except SteganographyError as e:
            messagebox.showerror("Error", str(e))
            return
        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error loading bundle: {e}")
            return

        self._apply_bundle(context, bundle, os.path.basename(filename))

    def _apply_bundle(self, context: str, bundle: dict, filename: str):
        """
        Stores bundle credentials internally and locks the corresponding
        password + marker fields to readonly with a placeholder display.
        Enables Remove Key, disables Key File while a bundle is active.
        Called by _browse_key_file() after successful decryption.
        """
        placeholder = "••••••••"

        if context == 'hide':
            self._hide_bundle_locked  = True
            self._hide_real_password  = bundle['password']
            self._hide_real_magic     = bundle['magic_seq']
            self._hide_real_end       = bundle['end_seq']
            self.password_entry.config(state="disabled", show="")
            self.password_var.set(placeholder)
            self.hide_magic_seq_var.set(placeholder)
            self.hide_end_seq_var.set(placeholder)
            self._set_frame_entries_state(self.hide_magic_entry_frame, "disabled")
            self._set_frame_entries_state(self.hide_end_entry_frame,   "disabled")
            self.password_toggle_btn.config(state="disabled")
            self.hide_pw_clear_btn.config(state="disabled")
            self.key_file_btn.config(state="disabled")
            self.hide_remove_key_btn.config(state="normal")
            self._update_capacity_display()

        elif context == 'extract':
            self._extract_bundle_locked = True
            self._extract_real_password = bundle['password']
            self._extract_real_magic    = bundle['magic_seq']
            self._extract_real_end      = bundle['end_seq']
            self.decrypt_password_entry.config(state="disabled", show="")
            self.decrypt_password_var.set(placeholder)
            self.extract_magic_seq_var.set(placeholder)
            self.extract_end_seq_var.set(placeholder)
            self._set_frame_entries_state(self.extract_magic_entry_frame, "disabled")
            self._set_frame_entries_state(self.extract_end_entry_frame,   "disabled")
            self.decrypt_password_toggle_btn.config(state="disabled")
            self.extract_pw_clear_btn.config(state="disabled")
            self.decrypt_key_file_btn.config(state="disabled")
            self.extract_remove_key_btn.config(state="normal")

        elif context == 'verify':
            self._verify_bundle_locked = True
            self._verify_real_password = bundle['password'] or None
            self._verify_real_magic    = bundle['magic_seq']
            self._verify_real_end      = bundle['end_seq']
            self.verify_password_var.set(placeholder)
            self.verify_magic_seq_var.set(placeholder)
            self.verify_end_seq_var.set(placeholder)
            self._set_frame_entries_state(self.verify_password_entry_frame, "disabled")
            self._set_frame_entries_state(self.verify_magic_entry_frame,    "disabled")
            self._set_frame_entries_state(self.verify_end_entry_frame,      "disabled")
            self.verify_key_file_btn.config(state="disabled")
            self.verify_remove_key_btn.config(state="normal")

        self._update_status(f"Key loaded into {context.capitalize()}: {filename}")

    def _clear_bundle(self, context: str):
        """
        Clears the bundle lock for the given context, re-enables all fields,
        re-enables Key File and disables Remove Key.
        Called by the 'Remove Key' buttons in Hide, Extract and Verify tabs.
        """
        if context == 'hide':
            self._hide_bundle_locked = False
            self._hide_real_password = self._hide_real_magic = self._hide_real_end = None
            self.password_var.set("")
            self.hide_magic_seq_var.set("")
            self.hide_end_seq_var.set("")
            self.password_entry.config(state="normal", show="*")
            self.password_toggle_btn.config(state="normal")
            self.hide_pw_clear_btn.config(state="normal")
            self.key_file_btn.config(state="normal")
            self.hide_remove_key_btn.config(state="disabled")
            self._set_frame_entries_state(self.hide_magic_entry_frame, "normal")
            self._set_frame_entries_state(self.hide_end_entry_frame,   "normal")
            self._update_capacity_display()

        elif context == 'extract':
            self._extract_bundle_locked = False
            self._extract_real_password = self._extract_real_magic = self._extract_real_end = None
            self.decrypt_password_var.set("")
            self.extract_magic_seq_var.set("")
            self.extract_end_seq_var.set("")
            self.decrypt_password_entry.config(state="normal", show="*")
            self.decrypt_password_toggle_btn.config(state="normal")
            self.extract_pw_clear_btn.config(state="normal")
            self.decrypt_key_file_btn.config(state="normal")
            self.extract_remove_key_btn.config(state="disabled")
            self._set_frame_entries_state(self.extract_magic_entry_frame, "normal")
            self._set_frame_entries_state(self.extract_end_entry_frame,   "normal")

        elif context == 'verify':
            self._verify_bundle_locked = False
            self._verify_real_password = self._verify_real_magic = self._verify_real_end = None
            self.verify_password_var.set("")
            self.verify_magic_seq_var.set("")
            self.verify_end_seq_var.set("")
            self._set_frame_entries_state(self.verify_password_entry_frame, "normal")
            self._set_frame_entries_state(self.verify_magic_entry_frame,    "normal")
            self._set_frame_entries_state(self.verify_end_entry_frame,      "normal")
            self.verify_key_file_btn.config(state="normal")
            self.verify_remove_key_btn.config(state="disabled")

        self._update_status(f"Key removed from {context.capitalize()}")

    @staticmethod
    def _set_frame_entries_state(frame, state: str):
        """
        Sets the state of all Entry and Button children inside a _make_entry_with_clear frame.
        Called by _apply_bundle() and _clear_bundle() to lock/unlock marker fields.
        """
        for child in frame.winfo_children():
            try:
                child.config(state=state)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Toggle-Helfer
    # ------------------------------------------------------------------

    def _toggle_password_visibility(self):
        """Toggles password visibility in Hide tab. Called by Show checkbox."""
        self.password_entry.config(show="" if self.show_password_var.get() else "*")

    def _toggle_decrypt_password_visibility(self):
        """Schaltet Passwort-Sichtbarkeit im Extract-Tab um. Wird von Checkbox aufgerufen."""
        self.decrypt_password_entry.config(show="" if self.show_decrypt_password_var.get() else "*")

    # ------------------------------------------------------------------
    # Kapazitäts- und Zeichenzähler-Logik
    # ------------------------------------------------------------------

    def _update_char_count(self, event=None):
        """
        Updates character counter, capacity display and progress bar.
        Capacity is always calculated without encryption overhead to avoid
        leaking information about whether encryption is in use.
        Called on KeyRelease and mouse click in the text input widget.
        """
        text = self.hide_text_widget.get("1.0", tk.END)
        char_count = len(text.strip())
        count_text = f"{char_count:,} characters"

        image_path = normalize_path(self.hide_image_var.get())
        magic_seq = self._hide_real_magic if self._hide_bundle_locked else self.hide_magic_seq_var.get()
        end_seq   = self._hide_real_end   if self._hide_bundle_locked else self.hide_end_seq_var.get()

        if image_path and os.path.exists(image_path):
            if not magic_seq or not end_seq:
                self.char_count_label.config(foreground="orange")
                count_text += " | Please define Start Marker and End Marker"
                self.capacity_progress.grid_remove()
            elif char_count > 0:
                try:
                    # Always calculate without encryption flag - capacity is approximate by design
                    steg = SecureSteganography(magic_sequence=magic_seq, end_delimiter=end_seq)
                    max_chars = steg.calculate_capacity(image_path, encrypted=False)

                    remaining = max_chars - char_count
                    usage_percent = (char_count / max_chars * 100) if max_chars > 0 else 100

                    if remaining >= 0:
                        if usage_percent >= 95:
                            count_text += (
                                f" | ~{remaining:,} characters remaining "
                                f"(~{usage_percent:.0f}% - close to limit)"
                            )
                            self.char_count_label.config(foreground="#B8500A")
                        else:
                            count_text += f" | ~{remaining:,} characters remaining (~{usage_percent:.0f}% used)"
                            self.char_count_label.config(foreground="dark green")
                    else:
                        count_text += f" | ~{abs(remaining):,} characters too many!"
                        self.char_count_label.config(foreground="red")

                    self.capacity_progress.grid(
                        row=3, column=0, sticky=(tk.W, tk.E), pady=(2, 8), padx=(5, 5))
                    self.capacity_progress_var.set(min(usage_percent, 100))

                    if usage_percent <= 70:
                        self.capacity_progress.configure(style='Green.Horizontal.TProgressbar')
                    elif usage_percent <= 90:
                        self.capacity_progress.configure(style='Yellow.Horizontal.TProgressbar')
                    elif usage_percent <= 95:
                        self.capacity_progress.configure(style='Red.Horizontal.TProgressbar')
                    else:
                        self.capacity_progress.configure(style='DarkRed.Horizontal.TProgressbar')

                except Exception as e:
                    self.char_count_label.config(foreground="red")
                    count_text += f" | Error: {e}"
                    self.capacity_progress.grid_remove()
            else:
                self.char_count_label.config(foreground="black")
                self.capacity_progress.grid_remove()
        else:
            self.char_count_label.config(foreground="black")
            self.capacity_progress.grid_remove()

        self.char_count_var.set(count_text)

    def _update_capacity_display(self):
        """
        Updates the capacity line above the text input field.
        Always calculates without encryption flag - capacity is approximate by design.
        Called after image selection or bundle load/clear.
        """
        image_path = normalize_path(self.hide_image_var.get())
        if not image_path or not os.path.exists(image_path):
            self.capacity_var.set("Select an image to see capacity")
            self._update_char_count()
            return
        try:
            magic_seq = self._hide_real_magic if self._hide_bundle_locked else self.hide_magic_seq_var.get()
            end_seq   = self._hide_real_end   if self._hide_bundle_locked else self.hide_end_seq_var.get()
            steg = SecureSteganography(magic_sequence=magic_seq, end_delimiter=end_seq)
            max_chars = steg.calculate_capacity(image_path, encrypted=False)
            img = Image.open(image_path)
            self.capacity_var.set(
                f"~{max_chars:,} characters max.  "
                f"(Image: {img.size[0]}x{img.size[1]} px)"
            )
            self._update_char_count()
        except Exception as e:
            self.capacity_var.set(f"Error calculating capacity: {e}")

    # ------------------------------------------------------------------
    # Status / Progress
    # ------------------------------------------------------------------

    def _update_progress(self, value: float):
        """Aktualisiert den globalen Fortschrittsbalken. Thread-sicher via _schedule()."""
        self.progress_var.set(value)

    def _update_status(self, message: str):
        """Aktualisiert die Statuszeile. Thread-sicher via _schedule()."""
        self.status_var.set(message)

    # ------------------------------------------------------------------
    # Kernoperationen (Worker-Threads)
    # ------------------------------------------------------------------

    def _hide_text(self):
        """
        Validates inputs in the main thread, then starts the hide worker thread.
        When a bundle is loaded, reads real credentials from internal storage
        instead of from the (placeholder-filled) UI fields.
        Called by the 'Hide Text' button.
        """
        image_path = normalize_path(self.hide_image_var.get())
        text = self.hide_text_widget.get("1.0", tk.END).strip()
        output_path = normalize_path(self.hide_output_var.get())

        if self._hide_bundle_locked:
            password = self._hide_real_password
            magic_seq = self._hide_real_magic
            end_seq   = self._hide_real_end
        else:
            password  = self.password_var.get() or None
            magic_seq = self.hide_magic_seq_var.get()
            end_seq   = self.hide_end_seq_var.get()

        if not image_path:
            messagebox.showerror("Error", "Please select an image.")
            return
        if not text:
            messagebox.showerror("Error", "Please enter some text.")
            return
        if not output_path:
            messagebox.showerror("Error", "Please select an output path.")
            return
        if not magic_seq or not end_seq:
            messagebox.showerror("Error",
                                 "Please enter Start Marker and End Marker." if not self._hide_bundle_locked
                                 else "No bundle loaded. Please load a key bundle first.")
            return

        def worker():
            try:
                self._schedule(self._update_status, "Hiding text...")
                steg = SecureSteganography(password, magic_sequence=magic_seq, end_delimiter=end_seq)
                result = steg.hide_text(
                    image_path, text, output_path,
                    lambda v: self._schedule(self._update_progress, v)
                )
                self._schedule(self._update_status, "Ready")
                self._schedule(self._update_progress, 0)
                # Textfeld nach erfolgreichem Verstecken leeren
                self._schedule(self._clear_text)
                self._schedule(
                    messagebox.showinfo, "Success",
                    f"Text hidden successfully!\n\n"
                    f"Output file: {result['output_path']}\n"
                    f"Text length: {result['text_length']:,} characters\n"
                    f"Encrypted: {'Yes' if result['encrypted'] else 'No'}\n"
                    f"Capacity used: {result['capacity_used']}"
                )
            except SteganographyError as e:
                self._schedule(self._update_status, "Ready")
                self._schedule(self._update_progress, 0)
                self._schedule(messagebox.showerror, "Steganography Error", str(e))
            except Exception as e:
                self._schedule(self._update_status, "Ready")
                self._schedule(self._update_progress, 0)
                self._schedule(messagebox.showerror, "Error", f"Unexpected error: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def _extract_text(self):
        """
        Validates inputs in the main thread, then starts the extract worker thread.
        When a bundle is loaded, reads real credentials from internal storage.
        Called by the 'Extract Text' button.
        """
        image_path = normalize_path(self.extract_image_var.get())

        if self._extract_bundle_locked:
            password  = self._extract_real_password
            magic_seq = self._extract_real_magic
            end_seq   = self._extract_real_end
        else:
            password  = self.decrypt_password_var.get() or None
            magic_seq = self.extract_magic_seq_var.get()
            end_seq   = self.extract_end_seq_var.get()

        if not image_path:
            messagebox.showerror("Error", "Please select an image.")
            return
        if not magic_seq or not end_seq:
            messagebox.showerror("Error", "Please enter Start Marker and End Marker.")
            return

        def worker():
            try:
                self._schedule(self._update_status, "Extracting text...")
                steg = SecureSteganography(password, magic_sequence=magic_seq, end_delimiter=end_seq)
                result = steg.extract_text(
                    image_path,
                    lambda v: self._schedule(self._update_progress, v)
                )

                def set_result_text():
                    self.extract_text_widget.config(state="normal")
                    self.extract_text_widget.delete("1.0", tk.END)
                    self.extract_text_widget.insert("1.0", result['text'])
                    self.extract_text_widget.config(state="disabled")

                self._schedule(set_result_text)
                self._schedule(self._update_status, "Ready")
                self._schedule(self._update_progress, 0)
                self._schedule(
                    messagebox.showinfo, "Success",
                    f"Text extracted successfully!\n\n"
                    f"Text length: {result['text_length']:,} characters\n"
                    f"Encrypted: {'Yes' if result['encrypted'] else 'No'}"
                )
            except SteganographyError as e:
                self._schedule(self._update_status, "Ready")
                self._schedule(self._update_progress, 0)
                self._schedule(messagebox.showerror, "Steganography Error", str(e))
            except Exception as e:
                self._schedule(self._update_status, "Ready")
                self._schedule(self._update_progress, 0)
                self._schedule(messagebox.showerror, "Error", f"Unexpected error: {e}")

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    # Tools-Tab Aktionen
    # ------------------------------------------------------------------

    def _check_capacity(self):
        """Calculates and displays approximate capacity of the selected image. Called by the Check button."""
        image_path = normalize_path(self.cap_image_var.get())
        if not image_path:
            messagebox.showerror("Error", "Please select an image.")
            return
        try:
            steg = SecureSteganography()
            max_chars = steg.calculate_capacity(image_path, encrypted=False)
            img = Image.open(image_path)
            self.capacity_result_var.set(
                f"Image: {img.size[0]}x{img.size[1]} px | "
                f"~{max_chars:,} characters max."
            )
            messagebox.showinfo(
                "Image Capacity",
                f"Image: {img.size[0]}x{img.size[1]} pixels\n\n"
                f"Approximate capacity: ~{max_chars:,} characters\n"
                f"(~{max_chars // 1000} KB of text)"
            )
        except Exception as e:
            self.capacity_result_var.set(f"Error: {e}")
            messagebox.showerror("Error", f"Capacity check failed: {e}")

    def _verify_image(self):
        """Checks whether an image contains valid hidden data. Called by the Check button."""
        image_path = normalize_path(self.verify_image_var.get())
        if not image_path:
            messagebox.showerror("Error", "Please select an image.")
            return

        if self._verify_bundle_locked:
            password  = self._verify_real_password
            magic_seq = self._verify_real_magic
            end_seq   = self._verify_real_end
        else:
            magic_seq = self.verify_magic_seq_var.get()
            end_seq   = self.verify_end_seq_var.get()
            password  = self.verify_password_var.get() or None

        if not magic_seq or not end_seq:
            messagebox.showerror("Error", "Please enter Start Marker and End Marker.")
            return
        try:
            self._update_status("Checking for hidden data...")
            steg = SecureSteganography(password, magic_sequence=magic_seq, end_delimiter=end_seq)
            if steg.verify_integrity(image_path):
                self.verify_result_var.set("Hidden data found!")
                messagebox.showinfo("Verification", "Image contains hidden data!")
            else:
                self.verify_result_var.set("No hidden data found")
                messagebox.showinfo("Verification", "No hidden data found or data is corrupted.")
            self._update_status("Ready")
        except Exception as e:
            self.verify_result_var.set(f"Fehler: {e}")
            self._update_status("Ready")
            messagebox.showerror("Error", f"Fehler bei Verifikation: {e}")

    def _clear_keygen_fields(self):
        """Leert alle drei Key-Generator-Eingabefelder. Wird vom Button aufgerufen."""
        self.keygen_pw_var.set("")
        self.keygen_magic_var.set("")
        self.keygen_end_var.set("")
        self.key_result_var.set("")

    def _generate_key(self):
        """
        Generates a fully random password and markers, asks for master password
        confirmation, encrypts and saves the bundle.
        Called by the 'Generate & Save' button.
        """
        pw    = SecureSteganography.generate_random_password()
        magic = SecureSteganography.generate_random_sequence()
        end   = SecureSteganography.generate_random_sequence()

        attempts = 0
        while end == magic and attempts < 10:
            end = SecureSteganography.generate_random_sequence()
            attempts += 1
        if end == magic:
            messagebox.showerror("Error", "Could not generate unique markers. Please try again.")
            return

        master = self.keygen_master_var.get()
        if not master:
            messagebox.showerror("Error",
                                 "Master Password is required.\n\n"
                                 "It encrypts the bundle file and is never stored.\n"
                                 "You will need it every time you load this bundle.")
            return

        # Confirm master password to prevent typos locking the user out
        confirm = _ask_password_confirm(
            self.root,
            title="Confirm Master Password",
            prompt="Re-enter Master Password to confirm:",
        )
        if confirm is None:
            return  # user cancelled
        if confirm != master:
            messagebox.showerror("Error",
                                 "Master passwords do not match.\n"
                                 "Bundle was NOT saved.")
            return

        filename = filedialog.asksaveasfilename(
            title="Save Encrypted Key Bundle",
            defaultextension=".key",
            filetypes=[("Key Files", "*.key"), ("All Files", "*.*")])
        if not filename:
            return

        try:
            SecureSteganography.save_key_bundle(filename, pw, magic, end, master)

            self.key_result_var.set(f"Saved (encrypted): {os.path.basename(filename)}")
            messagebox.showinfo(
                "Key Bundle Saved",
                f"Encrypted key bundle saved successfully!\n\n"
                f"File: {filename}\n\n"
                "The bundle is encrypted with your Master Password.\n"
                "WARNING: Keep the Master Password safe - it is NOT stored\n"
                "anywhere. Without it, this bundle cannot be opened."
            )
        except SteganographyError as e:
            self.key_result_var.set(f"Error: {e}")
            messagebox.showerror("Error", str(e))
        except Exception as e:
            self.key_result_var.set(f"Error: {e}")
            messagebox.showerror("Error", f"Unexpected error: {e}")

    # ------------------------------------------------------------------
    # Text-Hilfsaktionen
    # ------------------------------------------------------------------

    def _load_text_file(self):
        """Lädt eine Textdatei in das Eingabefeld. Wird vom Button aufgerufen."""
        filename = filedialog.askopenfilename(
            title="Load Text File",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if not filename:
            return
        for encoding in ('utf-8', 'latin-1'):
            try:
                with open(filename, 'r', encoding=encoding) as f:
                    content = f.read()
                self.hide_text_widget.delete("1.0", tk.END)
                self.hide_text_widget.insert("1.0", content)
                self._update_char_count()
                self._update_status(f"Text loaded: {os.path.basename(filename)}")
                return
            except UnicodeDecodeError:
                continue
            except Exception as e:
                messagebox.showerror("Error", f"Error loading file: {e}")
                return
        messagebox.showerror("Error", "Datei konnte mit keinem unterstützten Encoding gelesen werden.")

    def _paste_from_clipboard(self):
        """Fügt Text aus der Zwischenablage ins Eingabefeld ein. Wird vom Button aufgerufen."""
        try:
            import pyperclip
            clipboard_text = pyperclip.paste()
        except ImportError:
            try:
                clipboard_text = self.root.clipboard_get()
            except tk.TclError:
                messagebox.showwarning("Warning", "Zwischenablage ist leer oder enthält keinen Text.")
                return
        if clipboard_text:
            self.hide_text_widget.delete("1.0", tk.END)
            self.hide_text_widget.insert("1.0", clipboard_text)
            self._update_char_count()
            self._update_status("Text pasted from clipboard")

    def _copy_extracted_to_clipboard(self):
        """Kopiert den extrahierten Text in die Zwischenablage. Wird vom Button aufgerufen."""
        text = self.extract_text_widget.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Warning", "No extracted text to copy.")
            return
        try:
            import pyperclip
            pyperclip.copy(text)
        except ImportError:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.root.update()
        self._update_status("Extracted text copied to clipboard")

    def _save_extracted_text(self):
        """Speichert den extrahierten Text in eine Datei. Wird vom Button aufgerufen."""
        text = self.extract_text_widget.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Warning", "No text available to save.")
            return
        filename = filedialog.asksaveasfilename(
            title="Save Text",
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(text)
                messagebox.showinfo("Success", f"Text saved to: {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Error saving: {e}")

    def _clear_text(self):
        """Leert das Texteingabefeld. Wird vom Button aufgerufen."""
        self.hide_text_widget.delete("1.0", tk.END)
        self._update_char_count()
        self._update_status("Text field cleared")


# ------------------------------------------------------------------
# Einstiegspunkt
# ------------------------------------------------------------------

def main():
    """Hauptfunktion: initialisiert tkinter, setzt DPI-Awareness, startet Mainloop."""
    root = tk.Tk()

    try:
        if sys.platform.startswith('win'):
            try:
                from ctypes import windll
                windll.shcore.SetProcessDpiAwareness(1)
            except Exception:
                pass
            root.tk.call('tk', 'scaling', 1.3)
    except Exception:
        pass

    app = SteganographyGUI(root)

    root.update_idletasks()
    width = max(1000, root.winfo_width())
    height = max(900, root.winfo_height())
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f"{width}x{height}+{x}+{y}")

    def on_closing():
        root.quit()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nProgramm durch Benutzer beendet")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        try:
            root.destroy()
        except Exception:
            pass


if __name__ == "__main__":
    # Verify all required dependencies and crypto primitives at startup
    missing = []
    try:
        import numpy
    except ImportError:
        missing.append("numpy")
    try:
        import PIL
    except ImportError:
        missing.append("Pillow")
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
    except ImportError:
        missing.append("cryptography >= 41.0 (with Argon2id support)")

    if missing:
        print("Missing dependencies:")
        for m in missing:
            print(f"  - {m}")
        print("\nInstall with:  pip install Pillow numpy 'cryptography>=41'")
        sys.exit(1)

    # Quick self-test of the crypto primitives before showing the GUI
    try:
        import os as _os
        _salt  = _os.urandom(16)
        _nonce = _os.urandom(12)
        _kdf   = Argon2id(salt=_salt, length=32, iterations=1, lanes=1,
                          memory_cost=8, ad=None, secret=None)
        _key   = _kdf.derive(b"startup-selftest")
        _ct    = AESGCM(_key).encrypt(_nonce, b"ok", None)
        assert AESGCM(_key).decrypt(_nonce, _ct, None) == b"ok"
    except Exception as e:
        print(f"Crypto self-test failed: {e}")
        print("Your cryptography library may not support Argon2id.")
        print("Upgrade with:  pip install --upgrade 'cryptography>=41'")
        sys.exit(1)

    main()
