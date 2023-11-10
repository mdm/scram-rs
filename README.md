# Scram-rs

v 0.9

A SCRAM-SHA1, SCRAM-SHA256, SCRAM-SHA512, SCRAM-SHA512-PLUS, SCRAM-SHA256-PLUS client and server.  

## License:

MPL-2.0

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
- Dynamic instance i.e store the instance as dyn object instead of the generic struct

## Does not support:
- authzid (a=)

## What is not implemented by design
This crate does not open a remote connection to host for you. It does not contain a code to open a connection to any remote target. 
This crate contains only a SCRAM-SHA logic. Your program manages the connection itself, reception of the data itself and transmitting 
it back to client/server on its own. This crated performs only logical operaions on received data and retrns the result to your program.
This appreoach inreases a flexibility. This crate also implements a signalling so there is no need to implement a special error handling.

## Based on crates:  
- pbkdf2
- sha2 
- sha-1
- hmac
- md-5
- base64
- getrandom
- ring

## Features:

By default the following crates: [pbkdf2], [hmac], [sha2], [sha1] are included with this crate and a trait objects are availeble.
- `use_ring` - adds crate: [ring] to the crate and a trait objects becomes available.

Both features can not be used at the same time.

## Warnings:

- This crate does not open network connection to anywhere. And must never!
- This crate has never been audited, only static tests proofs the correctness of its operation.
- This crate uses unverified cryptography crates. There is no warranty that the operaion of those crates is correct all the time.

Author of this crate is not responsible for anything which may happen.

## Usage:  

see ./examples/ [there](https://gitlab.com/relkom/scram-rs/-/tree/master/examples)

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


