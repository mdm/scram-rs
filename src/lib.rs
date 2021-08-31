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
