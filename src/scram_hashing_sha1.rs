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

use hmac::{Hmac, Mac};
use sha1::{Sha1, Digest as Digest1};
use pbkdf2::pbkdf2;

use crate::{ScramServerError, ScramHashing, ScramResult, scram_error_map, ScramErrorCode};

/// A `ScramProvider` which provides SCRAM-SHA-1 and SCRAM-SHA-1-PLUS
/// based on the PBKDF2, Sha, Hmac
pub struct ScramSha1RustNative;

impl ScramHashing for ScramSha1RustNative 
{
    fn hash(data: &[u8]) -> Vec<u8> 
    {
        let hash = Sha1::digest(data);

        return Vec::from(hash.as_slice());
    }

    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
    {
        let mut mac = 
            Hmac::<Sha1>::new_from_slice(key)
                .map_err(|e| 
                    scram_error_map!(ScramErrorCode::ExternalError, ScramServerError::OtherError,
                        "hmac() HmacSha1 err, {}", e)
                )?;

        mac.update(data);
        
        let result = mac.finalize();
        
        return Ok( Vec::from(result.into_bytes().as_slice()) );
    }

    fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>> 
    {
        let mut result = vec![0; Sha1::output_size()]; //20

        pbkdf2::<Hmac<Sha1>>(password, salt, iterations.get(), &mut result)
            .map_err(|e| 
                scram_error_map!(ScramErrorCode::ExternalError, ScramServerError::OtherError,
                    "pbkdf2 Hmac::<Sha1> err, {}", e)
            )?;

        return Ok(result);
    }
}

#[cfg(feature = "use_ring")]
pub mod sha1_ring_based
{
    use std::num::NonZeroU32;

    use ring::{digest as ring_digest, hmac as ring_hmac, pbkdf2 as ring_pbkdf2};

    use crate::{ScramHashing, ScramResult};

    /// A `ScramProvider` which provides SCRAM-SHA-1 and SCRAM-SHA-1-PLUS
    /// based on the Ring
    pub struct ScramSha1Ring;

    impl ScramHashing for ScramSha1Ring 
    {
        fn hash(data: &[u8]) -> Vec<u8> 
        {
            let hash = ring_digest::digest(&ring_digest::SHA1_FOR_LEGACY_USE_ONLY, data);

            return Vec::from(hash.as_ref());
        }

        fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
        {
            let s_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, key);
            let mut mac = ring_hmac::Context::with_key(&s_key);

            mac.update(data);

            let ret: Vec<u8> = mac.sign().as_ref().into();

            return Ok(ret);
        }

        fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>> 
        {
            let mut salted = vec![0; ring_digest::SHA1_OUTPUT_LEN];

            ring_pbkdf2::derive(ring_pbkdf2::PBKDF2_HMAC_SHA1, iterations.into(), salt, password, &mut salted);

            return Ok(salted);
        }
    }
}

#[cfg(feature = "use_ring")]
pub use self::sha1_ring_based::*;

