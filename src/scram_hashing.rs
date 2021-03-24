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

use sha1::{Sha1, Digest as Digest1};
use sha2::{Sha256, Sha512, Digest as Digest2};
use hmac::{Hmac, Mac, NewMac, crypto_mac::InvalidKeyLength};
use pbkdf2::pbkdf2;

use super::scram_error::{ScramResult, ScramRuntimeError, ScramErrorCode};
use super::{scram_error, scram_error_map};


pub trait ScramHashing 
{
    /// A function which hashes the data using the hash function.
    fn hash(data: &[u8]) -> Vec<u8>;

    /// A function which performs an HMAC using the hash function.
    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>>;

    /// A function which does PBKDF2 key derivation using the hash function.
    fn derive(password: &[u8], salt: &[u8], iterations: u32) -> ScramResult<Vec<u8>>;
}

/// A `ScramProvider` which provides SCRAM-SHA-1 and SCRAM-SHA-1-PLUS
pub struct ScramSha1;

impl ScramHashing for ScramSha1 
{
    fn hash(data: &[u8]) -> Vec<u8> 
    {
        let hash = Sha1::digest(data);

        return Vec::from(hash.as_slice());
    }

    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
    {
        type HmacSha1 = Hmac<Sha1>;
        let mut mac = HmacSha1::new_varkey(key)
                                .map_err(|e| scram_error_map!(ScramErrorCode::ExternalError, 
                                                                "hmac() HmacSha1 err, {}", e))?;
        mac.update(data);
        let result = mac.finalize();
        
        return Ok(Vec::from(result.into_bytes().as_slice()));
    }

    fn derive(password: &[u8], salt: &[u8], iterations: u32) -> ScramResult<Vec<u8>> 
    {
        let mut result = vec![0; 20];
        pbkdf2::<Hmac<Sha1>>(password, salt, iterations, &mut result);

        return Ok(result);
    }
}

/// A `ScramProvider` which provides SCRAM-SHA-256 and SCRAM-SHA-256-PLUS
pub struct ScramSha256;

impl ScramHashing for ScramSha256 
{
    fn hash(data: &[u8]) -> Vec<u8> 
    {
        let hash = Sha256::digest(data);

        return Vec::from(hash.as_slice());
    }

    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
    {
        let mut mac = Hmac::<Sha256>::new_varkey(key)
                                    .map_err(|e| scram_error_map!(ScramErrorCode::ExternalError, 
                                        "hmac() Hmac::<Sha256> err, {}", e))?;
        mac.update(data);
        let result = mac.finalize();
        let ret = Vec::from(result.into_bytes().as_slice());

        return Ok(ret);
    }

    fn derive(password: &[u8], salt: &[u8], iterations: u32) -> ScramResult<Vec<u8>> 
    {

        let mut salted = vec![0; 32];
        pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut salted);

        return Ok(salted);
    }

}

/// A `ScramProvider` which provides SCRAM-SHA-512 and SCRAM-SHA-512-PLUS 
pub struct ScramSha512;

impl ScramHashing for ScramSha512 
{
    fn hash(data: &[u8]) -> Vec<u8> 
    {
        let hash = Sha512::digest(data);

        return Vec::from(hash.as_slice());
    }

    fn hmac(data: &[u8], key: &[u8]) -> ScramResult<Vec<u8>> 
    {
        let mut mac = Hmac::<Sha512>::new_varkey(key)
                                    .map_err(|e| scram_error_map!(ScramErrorCode::ExternalError, 
                                        "hmac() Hmac::<Sha512> err, {}", e))?;
        mac.update(data);
        let result = mac.finalize();
        let ret = Vec::from(result.into_bytes().as_slice());

        return Ok(ret);
    }

    fn derive(password: &[u8], salt: &[u8], iterations: u32) -> ScramResult<Vec<u8>> 
    {

        let mut salted = vec![0; 64];
        pbkdf2::<Hmac<Sha512>>(password, salt, iterations, &mut salted);

        return Ok(salted);
    }

}


