# Scram-rs

v 0.2

A SCRAM-SHA1, SCRAM-SHA256, SCRAM-SHA512 SCRAM-SHA256-PLUS client and server.  

Supports:  
- SHA-1 hasher
- SHA-256 hasher (tested with Postfix Dovecot SASL)
- SHA-512 hasher
- Client/Server sync
- Server Channel Binding TLS-Server-Endpoint 256, 512 untested
- Client Channel Binding TLS-Server-Endpoint 256, 512 untested
- a partial support (untested) of async which allows to integrate it in async code
  or use with async

Does not support:
- authzid (a=)

Based on:  
- pbkdf2
- sha2 
- sha-1
- hmac
- md-5
- base64
- getrandom

Usage:  

see ./examples/


