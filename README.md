# 🔐 Hide - A Secure LSB Steganography tool

> This is a Python program to encrypted text inside images - undetectable, authenticated, and open source.
> Vibe coded with the help of Claude Sonnet 4.6

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-GNUv3-green?style=flat-square)
![Crypto](https://img.shields.io/badge/Crypto-AES--256--GCM-orange?style=flat-square)
![KDF](https://img.shields.io/badge/KDF-Argon2id-red?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.2-lightgrey?style=flat-square)

A desktop application for hiding text inside images using **Least Significant Bit (LSB) steganography**, combined with **AES-256-GCM authenticated encryption** and **Argon2id key derivation**. The result is an image that looks identical to the original but contains an encrypted, tamper-evident hidden message.

---

## Features

### Steganography
- LSB embedding in RGB pixel channels - visually imperceptible
- Supports PNG, JPEG, BMP, GIF, TIFF as input
- Output always saved as **lossless PNG** to prevent compression artifacts destroying the payload
- 4-byte length prefix in the bitstream - extract reads exactly the right number of bytes, no guessing

### Cryptography
- **AES-256-GCM** authenticated encryption - confidentiality + integrity in one primitive
- **Argon2id** key derivation (256 MB RAM · 4 iterations · 4 lanes) - GPU-resistant password hashing
- **128-bit random salt** + **96-bit random nonce** generated fresh per operation - no two embeddings are identical even with the same password and text
- GCM authentication tag is verified **before** any plaintext is released - corrupt or tampered images are rejected
- All markers (start/end delimiters) are embedded **inside the ciphertext** - no structure is visible in raw image data
- **Uniform error messages** across all failure paths - no cryptographic oracle

### Key Bundles (`.key` files)
- Password and markers are **randomly generated** - the user never types them
- The entire bundle is encrypted with AES-256-GCM using an Argon2id-derived master key
- The file magic header (`SKBX`) is used as **GCM Additional Authenticated Data (AAD)** - tampering with the file header is detected
- Without the master password, the file is indistinguishable from random bytes

### Security Hardening
- **Decompression bomb protection** - images above 100 MP (≈ 10 000 × 10 000 px) are rejected before any processing
- **`secrets.choice()`** for all random generation - cryptographically unbiased, no modulo bias
- **`subprocess.run()`** instead of `os.system()` - no shell injection vector on Windows
- No plaintext secrets ever stored to disk

### Performance & Architecture
- **NumPy-vectorised** bit operations - 100–500× faster than pure Python loops
- **Thread-safe GUI** - all processing runs in worker threads, the main thread only handles UI; never freezes on large images
- Thread-to-GUI communication exclusively via `queue.Queue` + `root.after()` polling

---

## Usage

### Hiding text

1. Open the **Hide Text** tab
2. Select a source image with **Browse**
3. Choose an output path with **Save As**
4. Enter or paste the text to hide
5. Set a **Password** (optional - leave empty for unencrypted embedding)
6. Set **Start Marker** and **End Marker** (unique identifiers for your payload(aka text))
8. Click **Hide Text**

> 💡 Use a **Key Bundle** for maximum security - password and markers are randomly generated and stored encrypted. Load them with the **Key File** button. See below for more information!

<img width="1003" height="935" alt="How to hide" src="https://github.com/user-attachments/assets/72f99b0a-729c-49c5-a73f-2eafe1aeb2cf" />


### Extracting text

1. Open the **Extract Text** tab
2. Select the steganographic image
3. Enter the same **Password**, **Start Marker**, and **End Marker** used during embedding
4. Click **Extract Text**

<img width="999" height="930" alt="how to extract" src="https://github.com/user-attachments/assets/df5763b1-6011-4efe-919e-2a1f2c22144b" />



### Generating a Key Bundle

1. Open the **Tools** tab → **Generate Key Bundle**
2. Enter a **Master Password** (this is the only thing you need to remember)
3. Confirm the master password
4. Choose a save location - the `.key` file is written encrypted (**keep it in a very very save place**)

Load the bundle in any tab using the **Key File** button. The real credentials are never displayed. The **Master Passwort** must be re-entered upon use.

<img width="999" height="930" alt="How to generate key" src="https://github.com/user-attachments/assets/ed5ce37d-5477-420d-9784-58f8431386ee" />
<img width="982" height="185" alt="use key" src="https://github.com/user-attachments/assets/f475f019-04fd-4151-ada1-921ef03075da" />

---

## Installation

The Program is available as .exe or as .py.
For using .py, the following installation requirements are needed.

### Requirements

- Python 3.8 or newer
- pip

### Install dependencies

```bash
pip install Pillow numpy "cryptography>=41"
```

> **Note:** `cryptography >= 41` is required for Argon2id support.

### Run

```bash
python steganography_gui.py
```

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| [Pillow](https://python-pillow.org/) | ≥ 10.0 | Image loading and saving |
| [NumPy](https://numpy.org/) | ≥ 1.24 | Vectorised bit operations |
| [cryptography](https://cryptography.io/) | ≥ 41.0 | AES-256-GCM, Argon2id |

---
---

# For those who want more information on the backgrounds...

## How Does It Work? - Technical Background

## 1. Hiding Text Inside Images - LSB Steganography

A digital image is made up of millions of pixels. Each pixel has three colour channels: **Red, Green, and Blue (RGB)**. Each channel is stored as a number between 0 and 255 - in other words, as **8 bits**.

```
Example: A slightly reddish pixel
  Red:   198  →  1 1 0 0 0 1 1 0
  Green:  87  →  0 1 0 1 0 1 1 1
  Blue:   92  →  0 1 0 1 1 1 0 0
```

The **Least Significant Bit (LSB)** is the rightmost bit - the "least important" one. Changing it shifts the colour value by only ±1. On a scale of 0–255, that difference is completely invisible to the human eye. A Red of 198 and a Red of 199 are practically identical.

### The Idea

Take the message you want to hide and convert it into a sequence of bits:

```
Letter 'H' = 72 = 0 1 0 0 1 0 0 0
```

Those bits are then written one by one as the LSB of each pixel channel in the image:

```
Pixel 1, Red channel:    1100011[0]  →  1100011[0]   bit = 0
Pixel 1, Green channel:  0101011[1]  →  0101011[1]   bit = 1
Pixel 1, Blue channel:   0101110[0]  →  0101110[0]   bit = 0
Pixel 2, Red channel:    1001101[1]  →  1001101[0]   bit = 0  ← changed
...
```

The result: an image that looks **pixel-perfectly identical** to the original, but carries a complete encrypted message hidden in its invisible low-order bits.

### Capacity

Each pixel can store 3 bits (one per RGB channel). A typical photo at 1920 × 1080 pixels offers:

```
1920 × 1080 × 3 bits = 6,220,800 bits = 777,600 bytes ≈ 760 KB
```

That is roughly 760,000 characters of text - more than an entire novel.

### Why PNG and Not JPEG?

JPEG compression mathematically alters pixel values to reduce file size. In doing so, it destroys exactly the LSBs where the message is stored. PNG saves pixels losslessly - every single bit remains exactly as it was written.

---

## 2. Argon2id - Why Regular Hashing Is Not Enough

### The Problem With Weak Passwords

If someone finds an image with a hidden message, they might try to guess the password. With modern hardware - especially GPUs - billions of passwords can be tested per second. A simple algorithm like SHA-256 offers little protection here: it was deliberately designed to be fast, which means an attacker can try thousands of passwords per millisecond.

### What Argon2id Does Differently

**Argon2id** is a **memory-hard function** - an algorithm that deliberately **consumes large amounts of RAM** in order to make testing many passwords simultaneously expensive and slow.

The reasoning is straightforward: RAM cannot be parallelised as easily as raw compute power. A GPU may have thousands of cores, but each core has very limited memory. If every single password attempt requires 256 MB of RAM, a GPU with 8 GB can only run 31 attempts in parallel - instead of billions.

### The Parameters Used in This Application

| Parameter | Value | Meaning |
|-----------|-------|---------|
| Memory cost | 256 MB | Every decryption attempt occupies 256 MB of RAM |
| Iterations | 4 | The algorithm passes through memory 4 times |
| Parallelism | 4 lanes | Uses 4 CPU threads internally |
| Output | 32 bytes | 256-bit AES key |

A single attempt takes approximately **1–2 seconds** on typical desktop hardware. For the legitimate user: barely noticeable. For an attacker trying to brute-force millions of passwords: effectively impossible.

### The "id" - Best of Both Worlds

Argon2 comes in three variants. **Argon2id** combines the strengths of the other two:

- **Argon2d** - resistant to GPU attacks through data-dependent memory access patterns
- **Argon2i** - resistant to side-channel attacks through data-independent memory access patterns
- **Argon2id** - first half behaves like Argon2i, second half like Argon2d → protects against both attack classes simultaneously

Argon2id won the **Password Hashing Competition** in 2015 and is today recommended as the standard for password hashing by RFC 9106.

### The Flow in This Application

```
Password + random Salt (16 bytes)
           ↓
        Argon2id
  (256 MB · 4 iter · 4 lanes)
           ↓
    256-bit AES key
           ↓
  AES-256-GCM encryption
```

The **salt** is crucial here: it is randomly generated fresh for every encryption and stored inside the image payload. Even if two messages are encrypted with the same password, a completely different key is derived each time - rendering rainbow tables and precomputed attacks useless.

# A clear diagram about the encryption used in **Hide**
> Source file: "encryption_diagram.html"
<img width="2432" height="5517" alt="image" src="https://github.com/user-attachments/assets/964fedcf-35c9-45c7-992b-63728be98f2a" />





## Payload Format

### Encrypted payload

```
┌─────────────────────────────────────────────────────────────────────┐
│ 4 bytes   Length prefix (big-endian uint32)                         │
├─────────────────────────────────────────────────────────────────────┤
│ 1 byte    Version (0x01 = encrypted)                                │
│ 16 bytes  Argon2id salt (random per operation)                      │
│ 12 bytes  AES-GCM nonce (random per operation)                      │
│ N bytes   AES-256-GCM ciphertext                                    │
│              └─ start_marker + plaintext + end_marker (UTF-8)       │
│ 16 bytes  AES-GCM authentication tag                                │
└─────────────────────────────────────────────────────────────────────┘
```

### Unencrypted payload

```
┌─────────────────────────────────────────────────────────────────────┐
│ 4 bytes   Length prefix (big-endian uint32)                         │
├─────────────────────────────────────────────────────────────────────┤
│ 1 byte    Version (0x00 = plain)                                    │
│ N bytes   start_marker + plaintext + end_marker (UTF-8)             │
└─────────────────────────────────────────────────────────────────────┘
```

The entire stream is written into the **least significant bits** of the flattened RGB pixel array.

---

## Key Bundle Format

```
┌──────────────────────────────────────────────────────────────────┐
│ 4 bytes   Magic header: SKBX (also used as GCM AAD)              │
│ 1 byte    Version (0x01)                                         │
│ 16 bytes  Argon2id salt                                          │
│ 12 bytes  AES-GCM nonce                                          │
│ N bytes   AES-256-GCM ciphertext                                 │
│              └─ [PW]>>password\n[mSEQ]>>magic\n[eSEQ]>>end\n     │
│ 16 bytes  AES-GCM authentication tag                             │
└──────────────────────────────────────────────────────────────────┘
```

---

## Argon2id Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Memory cost | 262 144 KB (256 MB) | Increases cost for attackers with GPUs / ASICs |
| Iterations | 4 | Time hardening |
| Parallelism | 4 lanes | Thread utilisation |
| Key length | 32 bytes | 256-bit AES key |

These parameters follow the RFC 9106 "offline" profile for strong brute-force resistance. Key derivation takes approximately **1–2 seconds** on typical desktop hardware - intentional.

---

## Capacity

Image capacity depends on resolution. Each pixel channel stores 1 bit, so:

```
capacity (bytes) = (width × height × 3) / 8  −  overhead
```

| Image resolution | Approx. capacity |
|-----------------|-----------------|
| 800 × 600 | ~175 KB |
| 1920 × 1080 | ~760 KB |
| 3840 × 2160 | ~3 MB |

The application displays live capacity and a usage progress bar while you type.

---

## Security Considerations

- **Steganographic detectability**: Sequential LSB embedding is detectable by statistical steganalysis tools (chi-square test, RS analysis). This tool prioritises **cryptographic security** over steganographic stealth - an attacker who finds the hidden data still cannot read it without the password.
- **Password strength**: Argon2id provides strong brute-force resistance, but a weak password is still a weak password. Use the Key Bundle generator for maximum entropy.
- **Lossless output only**: Always use PNG as the output format. JPEG recompression destroys LSB data.

---

## Disclaimer

This software ("Hide - A Secure LSB Steganography Tool") is provided "as is", without warranty of any kind, either express or implied.
The author accepts no liability for:

- Loss, corruption, or inaccessibility of any data or files
- Loss of passwords, key files, or encrypted content
- Damage to hardware or software caused by using this program
- Legal consequences arising from the use of this software
- Security vulnerabilities exploited by third parties
- Any indirect, incidental, or consequential damages of any kind

Use of this software is entirely at your own risk. The user is solely responsible for securely storing passwords and key files. Lost passwords or key files cannot be recovered.
This software is intended for lawful purposes only. Using it to circumvent security systems, conceal illegal content, or engage in any other unlawful activity is strictly prohibited.

## License

GNUv3 License - see [LICENSE](LICENSE) for details.

---

## Acknowledgements

Built with Python 3.14 | tkinter | Pillow 12.0.0 | NumPy 2.4.2 | cryptography 46.0.5

