/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov, RELKOM s.r.o
 * Copyright (C) 2021-2022  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::num::NonZeroU32;

#[cfg(feature = "use_default")]
use sha1::{Sha1, Digest as Digest1};
#[cfg(feature = "use_default")]
use sha2::{Sha256, Sha512};
#[cfg(feature = "use_default")]
use hmac::{Hmac, Mac};
#[cfg(feature = "use_default")]
use pbkdf2::pbkdf2;

#[cfg(feature = "use_ring")]
use ring::{digest as ring_digest, hmac as ring_hmac, rand, pbkdf2 as ring_pbkdf2};

use super::scram_error::{ScramResult, ScramRuntimeError, ScramErrorCode};
use super::{scram_error_map};


pub trait ScramHashing 
{
    /// A function which hashes the data using the hash function.
    fn hash(data: &[u8]) -> Vec<u8>;

    /// A function which performs an HMAC using the hash function.
    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>>;

    /// A function which does PBKDF2 key derivation using the hash function.
    fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>>;
}

/// A `ScramProvider` which provides SCRAM-SHA-1 and SCRAM-SHA-1-PLUS
pub struct ScramSha1;

impl ScramHashing for ScramSha1 
{
    #[cfg(feature = "use_default")]
    fn hash(data: &[u8]) -> Vec<u8> 
    {
        let hash = Sha1::digest(data);

        return Vec::from(hash.as_slice());
    }

    #[cfg(feature = "use_ring")]
    fn hash(data: &[u8]) -> Vec<u8> 
    {
        let hash = ring_digest::digest(&ring_digest::SHA1_FOR_LEGACY_USE_ONLY, data);

        return Vec::from(hash.as_ref());
    }

    #[cfg(feature = "use_default")]
    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
    {
        let mut mac = 
            Hmac::<Sha1>::new_from_slice(key)
                .map_err(|e| scram_error_map!(ScramErrorCode::ExternalError, "hmac() HmacSha1 err, {}", e))?;

        mac.update(data);
        
        let result = mac.finalize();
        
        return Ok( Vec::from(result.into_bytes().as_slice()) );
    }

    #[cfg(feature = "use_ring")]
    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
    {
        let s_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
        let mut mac = ring_hmac::Context::with_key(&s_key);

        mac.update(data);

        let ret: Vec<u8> = mac.sign().as_ref().into();

        return Ok(ret);
    }

    #[cfg(feature = "use_default")]
    fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>> 
    {
        let mut result = vec![0; Sha1::output_size()]; //20
        pbkdf2::<Hmac<Sha1>>(password, salt, iterations.get(), &mut result);

        return Ok(result);
    }

    #[cfg(feature = "use_ring")]
    fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>> 
    {
        let mut salted = vec![0; ring_digest::SHA1_OUTPUT_LEN];

        ring_pbkdf2::derive(ring_pbkdf2::PBKDF2_HMAC_SHA1, iterations.into(), salt, password, &mut salted);

        return Ok(salted);
    }
}

/// A `ScramProvider` which provides SCRAM-SHA-256 and SCRAM-SHA-256-PLUS
pub struct ScramSha256;

impl ScramHashing for ScramSha256 
{
    #[cfg(feature = "use_default")]
    fn hash(data: &[u8]) -> Vec<u8> 
    {
        let hash = Sha256::digest(data);

        return Vec::from(hash.as_slice());
    }

    #[cfg(feature = "use_ring")]
    fn hash(data: &[u8]) -> Vec<u8> 
    {
        let hash = ring_digest::digest(&ring_digest::SHA256, data);

        return Vec::from(hash.as_ref());
    }

    #[cfg(feature = "use_default")]
    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
    {
        let mut mac = 
            Hmac::<Sha256>::new_from_slice(key)
                .map_err(|e| scram_error_map!(ScramErrorCode::ExternalError, "hmac() Hmac::<Sha256> err, {}", e))?;

        mac.update(data);

        let result = mac.finalize();
        let ret = Vec::from(result.into_bytes().as_slice());

        return Ok(ret);
    }

    #[cfg(feature = "use_ring")]
    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
    {
        let s_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA256, key);
        let mut mac = ring_hmac::Context::with_key(&s_key);

        mac.update(data);

        let ret: Vec<u8> = mac.sign().as_ref().into();

        return Ok(ret);
    }

    #[cfg(feature = "use_default")]
    fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>> 
    {

        let mut salted = vec![0; Sha256::output_size()]; // 32
        pbkdf2::<Hmac<Sha256>>(password, salt, iterations.get(), &mut salted);

        return Ok(salted);
    }

    #[cfg(feature = "use_ring")]
    fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>> 
    {
        let mut salted = vec![0; ring_digest::SHA256_OUTPUT_LEN];

        ring_pbkdf2::derive(ring_pbkdf2::PBKDF2_HMAC_SHA256, iterations.into(), salt, password, &mut salted);

        return Ok(salted);
    }

}

/// A `ScramProvider` which provides SCRAM-SHA-512 and SCRAM-SHA-512-PLUS 
pub struct ScramSha512;

impl ScramHashing for ScramSha512 
{
    #[cfg(feature = "use_default")]
    fn hash(data: &[u8]) -> Vec<u8> 
    {
        let hash = Sha512::digest(data);

        return Vec::from(hash.as_slice());
    }

    #[cfg(feature = "use_ring")]
    fn hash(data: &[u8]) -> Vec<u8> 
    {
        let hash = ring_digest::digest(&ring_digest::SHA512, data);

        return Vec::from(hash.as_ref());
    }

    #[cfg(feature = "use_default")]
    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
    {
        let mut mac = 
            Hmac::<Sha512>::new_from_slice(key)
                .map_err(|e| scram_error_map!(ScramErrorCode::ExternalError, "hmac() Hmac::<Sha512> err, {}", e))?;

        mac.update(data);
        
        let result = mac.finalize();
        let ret = Vec::from(result.into_bytes().as_slice());

        return Ok(ret);
    }

    #[cfg(feature = "use_ring")]
    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
    {
        let s_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, key);
        let mut mac = ring_hmac::Context::with_key(&s_key);

        mac.update(data);

        let ret: Vec<u8> = mac.sign().as_ref().into();

        return Ok(ret);
    }

    #[cfg(feature = "use_default")]
    fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>> 
    {

        let mut salted = vec![0; Sha512::output_size()]; //64
        pbkdf2::<Hmac<Sha512>>(password, salt, iterations.get(), &mut salted);

        return Ok(salted);
    }

    #[cfg(feature = "use_ring")]
    fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>> 
    {
        let mut salted = vec![0; ring_digest::SHA512_OUTPUT_LEN];

        ring_pbkdf2::derive(ring_pbkdf2::PBKDF2_HMAC_SHA512, iterations.into(), salt, password, &mut salted);

        return Ok(salted);
    }

}


