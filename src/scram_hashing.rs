/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::num::NonZeroU32;

use super::scram_error::ScramResult;

pub trait ScramHashing 
{
    /// A function which hashes the data using the hash function.
    fn hash(data: &[u8]) -> Vec<u8>;

    /// A function which performs an HMAC using the hash function.
    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>>;

    /// A function which does PBKDF2 key derivation using the hash function.
    fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>>;
}

/// All hashing code dedicated for SHA1. Both rust native and ring inplemetations.
pub use super::scram_hashing_sha1::*;

/// All hasing code dedicated for SHA256. Both rust native and ring inplemetations.
pub use super::scram_hashing_sha2::*;

/// All hashing code dedicated for SHA512. Both rust native and ring inplemetations.
pub use super::scram_hashing_sha5::*;
