# libefpix
A C implementation of the EFPIX protocol.

## Packet Types
- Unicast signed
- Unicast anonymous
- Signed broadcast
- Anonymous broadcast

## Cryptographic Security
- Ed25519 signatures for authentication
- X25519 key exchange for forward secrecy
- ChaCha20-Poly1305 AEAD encryption
- Blake2b hashing
- Forward secrecy through ephemeral keys

## Dependencies
- Monocypher (place the library files in the lib/ directory)
- POSIX-compliant system with getrandom() syscall support

## Build
Run `make` or use `nct build` (automatic library fetch)

## Warning
This implementation is experimental and has not undergone security audit.