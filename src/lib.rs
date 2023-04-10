/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov, RELKOM s.r.o
 * Copyright (C) 2021-2022  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

//! Scram-RS (Sync and Async)
//! 
//! Since v 0.4.2 this project is relicensed with MPLv2.0.
//! The contributors and authors agreed to change license:
//! Aleksandr Morozov
//! RELKOM s.r.o
//! 
//! Provides a SASL SCRAM:
//! - SHA1 
//! - SHA256 
//! - SHA512 
//! - -PLUS
//!
//! Features:
//! - `use_ring` - addes crate: [ring] as an alternative hashing and other crypto functions.
//!
//! For default crypto crates:
//! scram-rs = { version = "0.4", default-features = true}
//! 
//! For `ring` crypto crates:
//! scram-rs = { version = "0.4", default-features = false, features = ["use_ring"]}
//! 
//! ### scram_sha256_server() sync/async tests (DEBUG)
//! 
//! | iteration | rust-native | use_ring |
//! |-----------|-------------|----------|
//! | 1         | 152.30ms    | 16.96ms  |
//! | 2         | 143.78ms    | 16.52ms  |
//! | 3         | 144.70ms    | 16.04ms  |
//! 
//! 
//! ### scram_sha256_works() async tests (DEBUG)
//! 
//! | iteration | rust-native | use_ring |
//! |-----------|-------------|----------|
//! | 1         | 143.68ms    | 16.15ms  |
//! | 2         | 143.66ms    | 15.98ms  |
//! | 3         | 144.40ms    | 17.12ms  |
//! 
//! For usage see ./examples/
//! 
//! Files:
//! - scram.rs contains client/server sync and async protocol handler
//! - scram_sync.rs a synchronious realization of the protocol handler
//! - scram_async.rs an asynchronious realization of the protocol handler
//! - scram_parser.rs a scram message parser
//! - scram_state.rs a global state of the protocol handler
//! - scram_hashing.rs contains all supported hashers implementation
//! - scram_error.rs error reporting code
//! - scram_common.rs a common code
//! - scram_cb.rs a channel bind code
//! - scram_auth.rs a authentification callbacks and interface

extern crate async_trait;
extern crate getrandom;
extern crate base64;
extern crate pbkdf2;
extern crate hmac;
extern crate sha2;
extern crate sha1;

extern crate md5;

#[cfg(feature = "use_ring")]
extern crate ring;

pub mod scram;
pub mod scram_cb;
pub mod scram_auth;
pub mod scram_hashing;
pub mod scram_common;
pub mod scram_error;
pub mod scram_async;
pub mod scram_parser;
pub mod scram_state;
pub mod scram_sync;
#[macro_use]
pub mod scram_cbh;
mod scram_hashing_sha1;
mod scram_hashing_sha2;
mod scram_hashing_sha5;

pub use scram::*;
pub use scram_auth::*;
pub use scram_common::*;
pub use scram_cb::ChannelBindType;
pub use scram_hashing::*;
pub use scram_error::*;
pub use scram_cbh::*;

pub use async_trait::async_trait;


