# libefpix
 
A lightweight C implementation of the [EFPIX](https://github.com/shinymonitor/EFPIX) protocol — a zero-trust, encrypted flood protocol designed for privacy, resilience, and metadata protection in hostile network environments.
 
## Features
 
- Four packet types: unicast (signed or anonymous) and broadcast (signed or anonymous)
- Modern cryptographic suite via [libsodium](https://libsodium.org):
  - Ed25519 signatures for message authenticity
  - X25519 + XSalsa20-Poly1305 sealed-box encryption
  - BLAKE2b for hashing and PoW
- Fixed-size packets: no length-based metadata leakage
- Proof-of-work: spam protection and deduplication built into the decode path
- Single-header implementation
 
## Usage
 
See `example.c` for a minimal working example. 

See `test.c` for all four message modes and tamper/duplicate tests.

## Dependencies
 
- **[libsodium](https://libsodium.org) 1.0.18+**
 
## Warning
 
This implementation is experimental and has not undergone a formal security audit. It may be vulnerable to side-channel attacks. Use in production at your own risk.
