/*-
* Scram-rs
* Copyright (C) 2021  Aleksandr Morozov
* 
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU Lesser General Public
* License as published by the Free Software Foundation; either
* version 3 of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
* Lesser General Public License for more details.
* 
* You should have received a copy of the GNU Lesser General Public License
* along with this program; if not, write to the Free Software Foundation,
* Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

//! Scram-RS (Sync and Async)
//! 
//! Provides a SASL SCRAM:
//! - SHA1 
//! - SHA256 
//! - SHA512 
//! - -PLUS
//!
//! Features:
//! - `use_default` - uses crates: [pbkdf2], [hmac], [sha2], [sha1] as a common hasing libs
//! - `use_ring` - uses crates: [ring] as a common hashing lib
//!
//! For default crypto crates:
//! scram-rs = { version = "0.4", default-features = true}
//! 
//! For `ring` crypto crates:
//! scram-rs = { version = "0.4", default-features = false, features = ["use_ring"]}
//! 
//! ### scram_sha256_server() sync/async tests (DEBUG)
//! 
//! | iteration | use_default | use_ring |
//! |-----------|-------------|----------|
//! | 1         | 152.30ms    | 16.96ms  |
//! | 2         | 143.78ms    | 16.52ms  |
//! | 3         | 144.70ms    | 16.04ms  |
//! 
//! 
//! ### scram_sha256_works() async tests (DEBUG)
//! 
//! | iteration | use_default | use_ring |
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
#[cfg(feature = "use_default")]
extern crate pbkdf2;
#[cfg(feature = "use_default")]
extern crate hmac;
#[cfg(feature = "use_default")]
extern crate sha2;
#[cfg(feature = "use_default")]
extern crate sha1;

extern crate md5;

#[cfg(feature = "use_ring")]
extern crate ring;

#[cfg(all(feature = "use_default", feature = "use_ring"))]
compile_error!("both features: use_default and use_ring can not be used simultaniosly!");

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

pub use scram::*;
pub use scram_auth::*;
pub use scram_common::*;
pub use scram_cb::ClientChannelBindingType;
pub use scram_hashing::*;
pub use scram_error::*;

pub use async_trait::async_trait;
