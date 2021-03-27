# Scram-rs

A SCRAM-SHA1, SCRAM-SHA256, SCRAM-SHA512 SCRAM-SHA256-PLUS client and server.  

Supports:  
- SHA-1 hasher
- SHA-256 hasher (tested with Postfix Dovecot SASL)
- SHA-512 hasher
- Client/Server sync
- Server Channel Binding TLS-Server-Endpoint 256, 512 untested
- Client Channel Binding TLS-Server-Endpoint 256, 512 untested

Does not support:
- authzid (a=)
- async (will be available after sync version become fully tested)

Based on:  
- pbkdf2
- sha2 sha-1

Usage:  

see ./examples/


