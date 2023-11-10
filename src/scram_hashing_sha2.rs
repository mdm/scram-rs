/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::num::NonZeroU32;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2;
use sha1::{Digest as Digest1};

use crate::ScramHashing;

use super::scram_error::{ScramResult, ScramErrorCode};
use super::{scram_error_map};

/// A `ScramProvider` which provides SCRAM-SHA-256 and SCRAM-SHA-256-PLUS
/// based on the PBKDF2, Sha, Hmac
pub struct ScramSha256RustNative;

impl ScramHashing for ScramSha256RustNative 
{
    fn hash(data: &[u8]) -> Vec<u8> 
    {
        let hash = Sha256::digest(data);

        return Vec::from(hash.as_slice());
    }

    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
    {
        use crate::ScramServerError;

        let mut mac = 
            Hmac::<Sha256>::new_from_slice(key)
                .map_err(|e| 
                    scram_error_map!(ScramErrorCode::ExternalError, ScramServerError::OtherError,
                        "hmac() Hmac::<Sha256> err, {}", e)
                )?;

        mac.update(data);

        let result = mac.finalize();
        let ret = Vec::from(result.into_bytes().as_slice());

        return Ok(ret);
    }

    fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>> 
    {
        use crate::ScramServerError;

        let mut salted = vec![0; Sha256::output_size()]; // 32
        pbkdf2::<Hmac<Sha256>>(password, salt, iterations.get(), &mut salted)
            .map_err(|e| 
                scram_error_map!(ScramErrorCode::ExternalError, ScramServerError::OtherError,
                    "pbkdf2 Hmac::<Sha1> err, {}", e)
            )?;

        return Ok(salted);
    }
}


#[cfg(feature = "use_ring")]
pub mod sha256_ring_based
{
    use std::num::NonZeroU32;

    use ring::{digest as ring_digest, hmac as ring_hmac, pbkdf2 as ring_pbkdf2};

    use crate::{ScramHashing, ScramResult};

    /// A `ScramProvider` which provides SCRAM-SHA-256 and SCRAM-SHA-256-PLUS
    /// based on the Ring. 
    pub struct ScramSha256Ring;

    impl ScramHashing for ScramSha256Ring 
    {
        fn hash(data: &[u8]) -> Vec<u8> 
        {
            let hash = ring_digest::digest(&ring_digest::SHA256, data);

            return Vec::from(hash.as_ref());
        }

        fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
        {
            let s_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA256, key);
            let mut mac = ring_hmac::Context::with_key(&s_key);

            mac.update(data);

            let ret: Vec<u8> = mac.sign().as_ref().into();

            return Ok(ret);
        }

        fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>> 
        {
            let mut salted = vec![0; ring_digest::SHA256_OUTPUT_LEN];

            ring_pbkdf2::derive(ring_pbkdf2::PBKDF2_HMAC_SHA256, iterations.into(), salt, password, &mut salted);

            return Ok(salted);
        }

    }
}

#[cfg(feature = "use_ring")]
pub use self::sha256_ring_based::*;
