# Scram-rs

v 0.8

A SCRAM-SHA1, SCRAM-SHA256, SCRAM-SHA512, SCRAM-SHA512-PLUS, SCRAM-SHA256-PLUS client and server.  

## Supports:  
- SHA-1 hasher
- SHA-256 hasher (tested with Postfix Dovecot SASL)
- SHA-512 hasher
- Client/Server sync
- Server Channel Binding 256, 512 untested (user must implement the trait to provide necessary data)
- Client Channel Binding 256, 512 untested
- a partial support of async which allows to integrate it in async code
  or use with async
- Client/Server key (custom)
- Error handling `server-error` RFC5802 (`e=server-error-value`)

## Does not support:
- authzid (a=)

## What is not implemented by design
This crate does not handle a connection to a remote host for you. This is only a logic. Your program manages the connection, reception of the data and transmitting it back to client/server. This crated performs only logical operaions in received data and retrns the result.

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
| 1         | 98.02ms     | 16.96ms  |
| 2         | 98.69ms     | 16.52ms  |
| 3         | 95.27ms     | 16.04ms  |


### scram_sha256_works() async tests (DEBUG)

| iteration | use_default | use_ring |
|-----------|-------------|----------|
| 1         | 97.66ms     | 16.15ms  |
| 2         | 100.65ms    | 15.98ms  |
| 3         | 100.05ms    | 17.12ms  |


