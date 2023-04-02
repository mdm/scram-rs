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
 use sha2::Sha512;
 use hmac::{Hmac, Mac};
 use pbkdf2::pbkdf2;
 use sha1::{Digest as Digest1};
 
 use crate::ScramHashing;
 
 use super::scram_error::{ScramResult, ScramErrorCode};
 use super::{scram_error_map};

/// A `ScramProvider` which provides SCRAM-SHA-512 and SCRAM-SHA-512-PLUS 
/// based on the PBKDF2, Sha, Hmac
pub struct ScramSha512RustNative;

impl ScramHashing for ScramSha512RustNative 
{
    fn hash(data: &[u8]) -> Vec<u8> 
    {
        let hash = Sha512::digest(data);

        return Vec::from(hash.as_slice());
    }

    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
    {
        use crate::ScramServerError;

        let mut mac = 
            Hmac::<Sha512>::new_from_slice(key)
                .map_err(|e| 
                    scram_error_map!(ScramErrorCode::ExternalError, ScramServerError::OtherError, 
                        "hmac() Hmac::<Sha512> err, {}", e)
                )?;

        mac.update(data);
        
        let result = mac.finalize();
        let ret = Vec::from(result.into_bytes().as_slice());

        return Ok(ret);
    }

    fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>> 
    {
        use crate::ScramServerError;
        
        let mut salted = vec![0; Sha512::output_size()]; //64
        pbkdf2::<Hmac<Sha512>>(password, salt, iterations.get(), &mut salted)
            .map_err(|e| 
                scram_error_map!(ScramErrorCode::ExternalError, ScramServerError::OtherError,
                    "pbkdf2 Hmac::<Sha1> err, {}", e)
            )?;

        return Ok(salted);
    }
}

#[cfg(feature = "use_ring")]
pub mod sha512_ring_based
{
    use std::num::NonZeroU32;

    use ring::{digest as ring_digest, hmac as ring_hmac, pbkdf2 as ring_pbkdf2};

    use crate::{ScramHashing, ScramResult};

    /// A `ScramProvider` which provides SCRAM-SHA-256 and SCRAM-SHA-256-PLUS
    /// based on the Ring. 
    pub struct ScramSha512Ring;

    impl ScramHashing for ScramSha512Ring 
    {
        fn hash(data: &[u8]) -> Vec<u8> 
        {
            let hash = ring_digest::digest(&ring_digest::SHA512, data);

            return Vec::from(hash.as_ref());
        }

        fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
        {
            let s_key = ring_hmac::Key::new(ring_hmac::HMAC_SHA512, key);
            let mut mac = ring_hmac::Context::with_key(&s_key);

            mac.update(data);

            let ret: Vec<u8> = mac.sign().as_ref().into();

            return Ok(ret);
        }

        fn derive(password: &[u8], salt: &[u8], iterations: NonZeroU32) -> ScramResult<Vec<u8>> 
        {
            let mut salted = vec![0; ring_digest::SHA512_OUTPUT_LEN];

            ring_pbkdf2::derive(ring_pbkdf2::PBKDF2_HMAC_SHA512, iterations.into(), salt, password, &mut salted);

            return Ok(salted);
        }

    }
}

#[cfg(feature = "use_ring")]
pub use self::sha512_ring_based::*;
