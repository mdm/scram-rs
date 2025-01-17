/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use core::fmt;
use std::num::NonZeroU32;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose;

use crate::{scram_error_map, ScramErrorCode, ScramServerError};

use super::scram_error::ScramResult;

use super::scram_common::ScramCommon;
use super::scram_hashing::ScramHashing;

/// A Scram client/server key storage.
#[derive(Debug, PartialEq, Eq)]
pub struct ScramKey
{
    client_key: Option<Vec<u8>>,
    server_key: Option<Vec<u8>>,
}

impl ScramKey
{
    pub const DEFAULT_CLIENT_KEY: &'static [u8] = b"Client Key";
    pub const DEFAULT_SERVER_KEY: &'static [u8] = b"Server Key";

    pub 
    fn get_clinet_key(&self) -> &[u8]
    {
        match self.client_key
        {
            Some(ref key) => return key.as_slice(),
            None => return Self::DEFAULT_CLIENT_KEY,
        }
    }

    pub 
    fn get_server_key(&self) -> &[u8]
    {
        match self.server_key
        {
            Some(ref key) => return key.as_slice(),
            None => return Self::DEFAULT_SERVER_KEY,
        }
    }

    pub 
    fn new() -> Self
    {
        return Self{ client_key: None, server_key: None };
    }

    pub 
    fn set_client_key(&mut self, key: Vec<u8>)
    {
        self.client_key = Some(key);
    }

    pub 
    fn set_server_key(&mut self, key: Vec<u8>)
    {
        self.server_key = Some(key);
    }
}

/// A authentification callback returns this enum. 
/// 
/// The callback should use implemented functions to generate the result!
#[derive(Debug, PartialEq, Eq)]
pub enum ScramPassword
{
    /// Default state for initialization!
    /// Should never be returned from the authentification backend.
    None,

    /// User was not found in auth DB, anyway in order to avoid timing
    /// attacks, the fake data will be generated
    UserNotFound
    {
        /// salted and hashed (SHA-?) password
        salted_hashed_password: Vec<u8>,
        /// plaintext salt used (non base64)
        salt_b64: String,
        /// iteration count
        iterations: NonZeroU32,
        /// keys
        scram_keys: ScramKey,
    },

    /// User was found with or without salt data
    UserPasswordData
    {
        /// salted and hashed (SHA-?) password
        salted_hashed_password: Vec<u8>,
        /// plaintext salt used (non base64)
        salt_b64: String,
        /// iteration count
        iterations: NonZeroU32,
        /// keys
        scram_keys: ScramKey,
    }
}

impl Default for ScramPassword
{
    fn default() -> Self 
    {
        return Self::None;
    }
}

impl ScramPassword
{
    /// Returns true if [ScramPassword] is diffrent than None
    pub 
    fn is_ok(&self) -> bool
    {
        return *self != Self::None;
        /*match *self
        {
            Self::None => return false,
            _ => return true,
        }*/
    }

    /// Internal function to generate mock salt.
    fn scram_mock_salt() -> ScramResult<Vec<u8>>
    {
        //generate mock auth nonce (todo: to statically created)
        let mock_auth_nonce = 
            ScramCommon::sc_random(ScramCommon::MOCK_AUTH_NONCE_LEN)?;

        return Ok(mock_auth_nonce);
    }

    /// A program which utilizes this crate should call this function if user was not
    /// found in DB. The execution should not be interrupted.
    /// 
    /// # Throws
    /// 
    /// May throw an error.
    pub 
    fn not_found<S: ScramHashing>() -> ScramResult<Self>
    {
        // generate fake data
        let salt = ScramPassword::scram_mock_salt()?;

        let password_raw = ScramCommon::sc_random(ScramCommon::MOCK_AUTH_NONCE_LEN)?;

        let salted_password = S::derive(&password_raw, &salt, ScramCommon::SCRAM_DEFAULT_SALT_ITER)?;

        let ret = 
            Self::UserNotFound
            {
                salted_hashed_password: salted_password,
                salt_b64: general_purpose::STANDARD.encode(salt),
                iterations: ScramCommon::SCRAM_DEFAULT_SALT_ITER,
                scram_keys: ScramKey::new(),
            };

        return Ok(ret);
    }

    /// A program which uses this crate should call this function if user was found
    /// but password is encoded as plain text. This function requires that the correct
    /// [ScramHashing] which was previously used to initialize the server, should be used.
    /// 
    /// # Arguments
    /// 
    /// * `pass` - a plaintext password
    /// 
    /// # Throws
    /// 
    /// May throw an error.
    pub 
    fn found_plaintext_password<S>(pass: &[u8], scram_keys_opt: Option<ScramKey>) -> ScramResult<Self>
    where S: ScramHashing
    {
        //generate salt and iterations
        let salt = ScramPassword::scram_mock_salt()?;

        let salted_password = 
            S::derive(pass, &salt, ScramCommon::SCRAM_DEFAULT_SALT_ITER)?;

        let ret = 
            Self::UserPasswordData
            {
                salted_hashed_password: salted_password,
                salt_b64: general_purpose::STANDARD.encode(salt),
                iterations: ScramCommon::SCRAM_DEFAULT_SALT_ITER,
                scram_keys: scram_keys_opt.unwrap_or(ScramKey::new()),
            };

        return Ok(ret);
    }

    /// A program which uses this crate should call this function if user was found
    /// but password is encoded as plain text and server uses custom iteration number. 
    /// A function requires that the correct [ScramHashing] which was previously used to 
    /// initialize the server, should be used.
    /// 
    /// # Arguments
    /// 
    /// * `pass` - a plaintext password
    /// 
    /// # Throws
    /// 
    /// May throw an error.
    pub 
    fn found_plaintext_password_with_iterations<S>(
        pass: &[u8], 
        iterations: NonZeroU32, 
        scram_keys_opt: Option<ScramKey>
    ) -> ScramResult<Self>
    where S: ScramHashing
    {
        //generate salt and iterations
        let salt = ScramPassword::scram_mock_salt()?;

        let salted_password = S::derive(pass, &salt, iterations)?;

        let ret = 
            Self::UserPasswordData
            {
                salted_hashed_password: salted_password,
                salt_b64: general_purpose::STANDARD.encode(salt),
                iterations: iterations,
                scram_keys: scram_keys_opt.unwrap_or(ScramKey::new()),
            };

        return Ok(ret);
    }

    /// A program which utilizes this crate should call this function if user was found
    /// but password was salted and hashed and salt with iterations count were provided.
    /// 
    /// # Arguments
    /// 
    /// * `salted_hashed_password` - a salted and hashed password
    /// 
    /// * `salt` - a salt
    /// 
    /// * `iterations` - iterations count
    /// 
    /// # Throws
    /// 
    /// May throw an error.
    pub 
    fn found_secret_password(
        salted_hashed_password: Vec<u8>, 
        salt_base64: String, 
        iterations: NonZeroU32,
        scram_keys_opt: Option<ScramKey>
    ) -> Self
    {
        return 
            Self::UserPasswordData
            {
                salted_hashed_password: salted_hashed_password,
                salt_b64: salt_base64,
                iterations: iterations,
                scram_keys: scram_keys_opt.unwrap_or(ScramKey::new()),
            };
    }

    /// A program which utilizes this crate should call this function if user was found
    /// but password was salted and hashed and salt with iterations count were provided.
    /// 
    /// # Arguments
    /// 
    /// * `salted_hashed_password` - a base64 salted and hashed password
    /// 
    /// * `salt` - a salt
    /// 
    /// * `iterations` - iterations count
    /// 
    /// # Throws
    /// 
    /// May throw an error.
    pub 
    fn found_secret_base64_password(
        salted_hashed_password: String, 
        salt_base64: String, 
        iterations: NonZeroU32,
        scram_keys_opt: Option<ScramKey>
    ) -> ScramResult<Self>
    {
        let shp = 
            general_purpose::STANDARD.decode(salted_hashed_password)
                .map_err(|e| 
                    scram_error_map!(ScramErrorCode::ExternalError, ScramServerError::OtherError,
                        "can not decode salted and hashed password in [found_secret_base64_password], {}", e)
                )?;

        return Ok(
            Self::UserPasswordData
            {
                salted_hashed_password: shp,
                salt_b64: salt_base64,
                iterations: iterations,
                scram_keys: scram_keys_opt.unwrap_or(ScramKey::new()),
            }
        );
    }

    /// A function which can be used for salted password generation from
    /// provided parameters.
    /// 
    /// # Arguments
    /// 
    /// * `pass_plain` - a reference to the password in plain format
    /// 
    /// * `salt_plain` - a optional value which allows to set custom salt in
    /// in plain text.
    /// 
    /// * `iter` - an aoptional value which allows to set custom digit of
    /// iterations. The default is [ScramCommon::SCRAM_DEFAULT_SALT_ITER]
    /// 
    /// # Throws
    /// May throw an error.
    /// 
    /// # Returns
    /// 
    /// Instance of [ScramPassword::UserPasswordData] 
    pub 
    fn salt_password_with_params<U, S>(
        pass_plain: U, 
        salt_plain: Option<Vec<u8>>, 
        iter: Option<NonZeroU32>,
        scram_keys_opt: Option<ScramKey>
    ) -> ScramResult<Self>
    where S: ScramHashing, U: AsRef<[u8]>
    {
        let salt = 
            match salt_plain
            {
                Some(r) => r,
                None => ScramPassword::scram_mock_salt()?
            };
        
        let iterations = 
            match iter
            {
                Some(r) => r,
                None => ScramCommon::SCRAM_DEFAULT_SALT_ITER
            };

        let salted_password = S::derive(pass_plain.as_ref(), &salt, iterations)?;

        let ret = 
            Self::UserPasswordData
            {
                salted_hashed_password: salted_password,
                salt_b64: general_purpose::STANDARD.encode(salt),
                iterations: iterations,
                scram_keys: scram_keys_opt.unwrap_or(ScramKey::new()),
            };

        return Ok(ret);
    }

    /// Returns the reference to salt. Will panic! when misused.
    pub 
    fn get_salt_base64(&self) -> &String
    {
        match *self
        {
            Self::None => panic!("misuse get_salt()"),
            Self::UserNotFound{ ref salt_b64, .. } => return salt_b64,
            Self::UserPasswordData{ ref salt_b64, .. } => return salt_b64,
        }
    }

    /// Returns the iteration count. Will panic! when misused.
    pub 
    fn get_iterations(&self) -> NonZeroU32
    {
        match *self
        {
            Self::None => panic!("misuse get_iterations()"),
            Self::UserNotFound{ ref iterations, .. } => return *iterations,
            Self::UserPasswordData{ ref iterations, .. } => return *iterations,
        }
    }

    /// Returns the salted and hashed password. Will panic! when misused.
    pub 
    fn get_salted_hashed_password(&self) -> &[u8]
    {
        match *self
        {
            Self::None => panic!("misuse get_salted_hashed_password()"),
            Self::UserNotFound{ref salted_hashed_password, ..} => return salted_hashed_password.as_slice(),
            Self::UserPasswordData{ref salted_hashed_password, ..} => return salted_hashed_password.as_slice(),
        }
    }

    pub 
    fn get_scram_keys(&self) -> &ScramKey
    {
        match *self
        {
            Self::None => panic!("misuse get_salted_hashed_password()"),
            Self::UserNotFound{ref scram_keys, ..} => return scram_keys,
            Self::UserPasswordData{ref scram_keys, ..} => return scram_keys,
        }
    }
}

/// A authentification backend which is behind the SCRAM lib.
/// A program which uses this crate should implement this trait to its auth
/// instance.
/// 
/// # Examples
/// 
/// ```
/// struct AuthServer
/// {
///     password: String,   
/// }
/// 
/// impl AuthServer
/// {
///       fn lookup(&self, username: &str) -> Option<String>
///         { return Some(self.password.clone());}
/// }
/// use async_trait::async_trait; 
/// use scram_rs::scram_error::ScramResult;
/// use scram_rs::scram_hashing::ScramSha256;
/// use scram_rs::scram_auth::{ScramAuthServer, ScramPassword};
/// impl ScramAuthServer<ScramSha256> for AuthServer
/// {
///     fn get_password_for_user(&self, username: &str) -> ScramResult<ScramPassword>
///     {
///         let password = match self.lookup(username)
///         {
///             Some(r) => ScramPassword::found_plaintext_password::<ScramSha256>(r.as_bytes()),
///             None => ScramPassword::not_found::<ScramSha256>()
///         };
/// 
///         return password;
/// 
///     }
/// }
/// ```
pub trait ScramAuthServer<S: ScramHashing>: fmt::Debug
{
    fn get_password_for_user(&self, username: &str) -> ScramResult<ScramPassword>;
}

/// A authentification backend which is behind the SCRAM lib.
/// A program which uses this crate should implement this trait to its auth
/// instance.
/// 
/// # Examples
/// 
/// ```
/// struct AuthServer
/// {
///     password: String,   
/// }
/// 
/// impl AuthServer
/// {
///       fn lookup(&self, username: &str) -> Option<String>
///         { return Some(self.password.clone());}
/// }
/// use async_trait::async_trait; 
/// use scram_rs::scram_error::ScramResult;
/// use scram_rs::scram_hashing::ScramSha256;
/// use scram_rs::scram_auth::{AsyncScramAuthServer, ScramPassword};
/// #[async_trait]
/// impl AsyncScramAuthServer<ScramSha256> for AuthServer
/// {
///     async fn get_password_for_user(&self, username: &str) -> ScramResult<ScramPassword>
///     {
///         let password = match self.lookup(username)
///         {
///             Some(r) => ScramPassword::found_plaintext_password::<ScramSha256>(r.as_bytes()),
///             None => ScramPassword::not_found::<ScramSha256>()
///         };
/// 
///         return password;
/// 
///     }
/// }
/// ```
#[async_trait]
pub trait AsyncScramAuthServer<S: ScramHashing>: fmt::Debug
{
    async fn get_password_for_user(&self, username: &str) -> ScramResult<ScramPassword>;
}

/// A authentification backend which is behind the SCRAM lib.
/// A program which uses this crate should implement this trait to its auth
/// instance.
/// 
/// # Examples
/// 
/// ```
/// impl ScramAuthClient for <ProgramStruct>
/// {
///     fn get_username(&self) -> &str
///     {
///         return &self.username;
///     }
/// 
///     fn get_password(&self) -> &str
///     {
///         return &self.password;
///     }
/// }
/// ```
pub trait ScramAuthClient: fmt::Debug
{
    /// This function must return plain text username
    fn get_username(&self) -> &str;
    /// This function must return plain text password
    fn get_password(&self) -> &str;
    /// This function returns a ref to [ScramKey]
    fn get_scram_keys(&self) -> &ScramKey;
}


/// A authentification backend which is behind the SCRAM lib.
/// A program which uses this crate should implement this trait to its auth
/// instance.
/// 
/// # Examples
/// 
/// ```
/// use async_trait::async_trait; 
/// #[async_trait]
/// impl AsyncScramAuthClient for <ProgramStruct>
/// {
///     async fn get_username(&self) -> &str
///     {
///         return &self.username;
///     }
/// 
///     async fn get_password(&self) -> &str
///     {
///         return &self.password;
///     }
/// }
/// ```
#[async_trait]
pub trait AsyncScramAuthClient: fmt::Debug
{
    /// This function must return plain text username
    async fn get_username(&self) -> &str;
    /// This function must return plain text password
    async fn get_password(&self) -> &str;
    /// This function returns a ref to [ScramKey]
    async fn get_scram_keys(&self) -> &ScramKey;
}

#[cfg(test)]
mod tests
{
    use std::time::Instant;
    use crate::ScramSha256RustNative;

    use super::*;

    #[test]
    fn test_exec_time()
    {
        let start = Instant::now();

        let res = ScramPassword::not_found::<ScramSha256RustNative>();
        assert_eq!(res.is_ok(), true);

        let el = start.elapsed();
        println!("not found took: {:?}", el);

        let start = Instant::now();

        let res = ScramPassword::found_plaintext_password::<ScramSha256RustNative>(b"123", None);
        assert_eq!(res.is_ok(), true);
        
        let el = start.elapsed();
        println!("found_plaintext_password: {:?}", el);

    }

    #[test]
    fn test_password_gen()
    {
        let start = Instant::now();

        let res = 
            ScramPassword::salt_password_with_params::<_, ScramSha256RustNative>(
                "pencil".to_string().into_bytes(), 
                Some("test".to_string().into_bytes()), 
                Some(NonZeroU32::new(4096).unwrap()),
                None,
            );

        let el = start.elapsed();
        println!("test_password_gen: {:?}", el);

        assert_eq!(res.is_ok(), true, "{}", res.err().unwrap());

        let res = res.unwrap();

        assert_eq!(res.get_iterations().get(), 4096);
        assert_eq!(res.get_salt_base64().as_str(), "dGVzdA==");
        assert_eq!(res.get_salted_hashed_password(), 
            general_purpose::STANDARD.decode("afBEmfdaTuiwYy1yoCIQ8XJJ1Awzo3Ha5Mf2aLTRHhs=").unwrap());

        return;
    }

    #[test]
    fn test_if()
    {
        let res = ScramPassword::default();

        assert_eq!(res.is_ok(), false);
    }
}
