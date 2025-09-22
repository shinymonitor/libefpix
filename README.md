# libefpix
A lightweight C implementation of the [EFPIX](https://github.com/shinymonitor/EFPIX) protocol, a zero-trust, encrypted flood protocol designed for privacy, resilience, and metadata protection in hostile network environments.

## Features
- Four Packet Types: Supports unicast (signed/anonymous) and broadcast (signed/anonymous) messages.
- Modern Cryptographic Suite:
    - Ed25519 signatures for message authenticity.
    - X25519 key exchange for deriving shared secrets.
    - Perfect Forward Secrecy through the use of ephemeral keys for each message.
    - ChaCha20-Poly1305 AEAD for fast, secure, and tamper-proof authenticated encryption.
    - BLAKE2b for high-speed hashing and message identification.
- Minimalist Design: Written in C with a single dependency.

## Usage
See `src/example.c` for usage and tests

## Dependencies
- Monocypher 4.0.1+: A single-file, audited, public-domain crypto library. Place all 4 monocypher .c and .h files in the lib/ directory, or use the automatic fetch feature in nct.

- POSIX-compliant system: Requires getrandom() syscall for secure random number generation.

## Build
Run make for a standard build. Alternatively, if you have NCT installed, you can use nct build.

## Warning
This implementation is experimental and has not undergone a formal security audit. It may be vulnerable to side-channel attacks. Use in production at your own risk.
