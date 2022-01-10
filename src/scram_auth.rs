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

use async_trait::async_trait;

use super::scram_error::{ScramResult};

use super::scram_common::ScramCommon;
use super::scram_hashing::ScramHashing;

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
                salt_b64: base64::encode(salt),
                iterations: ScramCommon::SCRAM_DEFAULT_SALT_ITER,
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
    fn found_plaintext_password<S: ScramHashing>(pass: &[u8]) -> ScramResult<Self>
    {
        //generate salt and iterations
        let salt = ScramPassword::scram_mock_salt()?;

        let salted_password = 
            S::derive(pass, &salt, ScramCommon::SCRAM_DEFAULT_SALT_ITER)?;

        let ret = 
            Self::UserPasswordData
            {
                salted_hashed_password: salted_password,
                salt_b64: base64::encode(salt),
                iterations: ScramCommon::SCRAM_DEFAULT_SALT_ITER,
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
        iterations: NonZeroU32
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
                salt_b64: base64::encode(salt),
                iterations: iterations,
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
        iterations: NonZeroU32
    ) -> Self
    {
        return 
            Self::UserPasswordData
            {
                salted_hashed_password: salted_hashed_password,
                salt_b64: salt_base64,
                iterations: iterations,
            };
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
        iter: Option<NonZeroU32>
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
                salt_b64: base64::encode(salt),
                iterations: iterations,
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
            Self::UserNotFound{ref salted_hashed_password, ..} => return &salted_hashed_password,
            Self::UserPasswordData{ref salted_hashed_password, ..} => return &salted_hashed_password,
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
pub trait ScramAuthServer<S: ScramHashing>
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
pub trait AsyncScramAuthServer<S: ScramHashing>
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
pub trait ScramAuthClient
{
    /// This function must return plain text username
    fn get_username(&self) -> &str;
    /// This function must return plain text password
    fn get_password(&self) -> &str;
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
pub trait AsyncScramAuthClient
{
    /// This function must return plain text username
    async fn get_username(&self) -> &str;
    /// This function must return plain text password
    async fn get_password(&self) -> &str;
}

#[test]
fn test_speed()
{
    use std::time::Instant;
    use super::scram_hashing::ScramSha256;

    let start = Instant::now();

    let res = ScramPassword::not_found::<ScramSha256>();
    assert_eq!(res.is_ok(), true);

    let el = start.elapsed();
    println!("not found took: {:?}", el);

    let start = Instant::now();

    let res = ScramPassword::found_plaintext_password::<ScramSha256>(b"123");
    assert_eq!(res.is_ok(), true);
    
    let el = start.elapsed();
    println!("found_plaintext_password: {:?}", el);

}

#[test]
fn test_password_gen()
{
    use std::time::Instant;
    use super::scram_hashing::ScramSha256;

    let start = Instant::now();

    let res = 
        ScramPassword::salt_password_with_params::<_, ScramSha256>(
            "pencil".to_string().into_bytes(), 
            Some("test".to_string().into_bytes()), 
            Some(NonZeroU32::new(4096).unwrap())
        );

    let el = start.elapsed();
    println!("test_password_gen: {:?}", el);

    assert_eq!(res.is_ok(), true, "{}", res.err().unwrap());

    let res = res.unwrap();

    assert_eq!(res.get_iterations().get(), 4096);
    assert_eq!(res.get_salt_base64().as_str(), "dGVzdA==");
    assert_eq!(res.get_salted_hashed_password(), base64::decode("afBEmfdaTuiwYy1yoCIQ8XJJ1Awzo3Ha5Mf2aLTRHhs=").unwrap());

    return;
}

#[test]
fn test_if()
{
    let res = ScramPassword::default();

    assert_eq!(res.is_ok(), false);
}