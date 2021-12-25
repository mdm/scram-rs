# Scram-rs

v 0.4

A SCRAM-SHA1, SCRAM-SHA256, SCRAM-SHA512 SCRAM-SHA256-PLUS client and server.  

## Supports:  
- SHA-1 hasher
- SHA-256 hasher (tested with Postfix Dovecot SASL)
- SHA-512 hasher
- Client/Server sync
- Server Channel Binding TLS-Server-Endpoint 256, 512 untested
- Client Channel Binding TLS-Server-Endpoint 256, 512 untested
- a partial support (untested) of async which allows to integrate it in async code
  or use with async

## Does not support:
- authzid (a=)

## Based on:  
- pbkdf2
- sha2 
- sha-1
- hmac
- md-5
- base64
- getrandom
- ring

## Features:
- `use_default` - uses crates: [pbkdf2], [hmac], [sha2], [sha1] as a common hasing libs
- `use_ring` - uses crates: [ring] as a common hashing lib

Both features can not be used at the same time.

## Usage:  

see ./examples/

## Test based benchmarks:

### scram_sha256_server() sync/async tests (DEBUG)

| iteration | use_default | use_ring |
|-----------|-------------|----------|
| 1         | 152.30ms    | 16.96ms  |
| 2         | 143.78ms    | 16.52ms  |
| 3         | 144.70ms    | 16.04ms  |


### scram_sha256_works() async tests (DEBUG)

| iteration | use_default | use_ring |
|-----------|-------------|----------|
| 1         | 143.68ms    | 16.15ms  |
| 2         | 143.66ms    | 15.98ms  |
| 3         | 144.40ms    | 17.12ms  |

