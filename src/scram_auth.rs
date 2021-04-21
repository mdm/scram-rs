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

use super::scram_error::{ScramResult, ScramRuntimeError, ScramErrorCode};
use super::{scram_error, scram_error_map};

use super::scram_common::ScramCommon;
use super::scram_hashing::ScramHashing;

/// A authentification callback returns this enum. 
/// 
/// The callback should use implemented functions to generate the result!
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
        salt: Vec<u8>,
        /// iteration count
        iterations: u32,
    },

    /// User was found with or without salt data
    UserPasswordData
    {
        /// salted and hashed (SHA-?) password
        salted_hashed_password: Vec<u8>,
        /// plaintext salt used (non base64)
        salt: Vec<u8>,
        /// iteration count
        iterations: u32,
    }
}

impl ScramPassword
{
    /// A default initialization. A program which utilizes this crate should 
    /// never use this function.
    pub fn default() -> Self
    {
        return Self::None;
    }

    /// Internal function to generate mock salt.
    fn scram_mock_salt() -> ScramResult<Vec<u8>>
    {
        //generate mock auth nonce (todo: to statically created)
        let mock_auth_nonce = ScramCommon::sc_random(ScramCommon::MOCK_AUTH_NONCE_LEN)?;

        return Ok(mock_auth_nonce);
    }

    /// A program which utilizes this crate should call this function if user was not
    /// found in DB. The execution should not be interrupted.
    /// 
    /// # Throws
    /// 
    /// May throw an error.
    pub fn not_found<S: ScramHashing>() -> ScramResult<Self>
    {
        // generate fake data
        let salt = ScramPassword::scram_mock_salt()?;

        let password_raw = ScramCommon::sc_random(ScramCommon::MOCK_AUTH_NONCE_LEN)?;

        let salted_password = S::derive(&password_raw, &salt, ScramCommon::SCRAM_DEFAULT_SALT_ITER)?;

        let ret = Self::UserNotFound
            {
                salted_hashed_password: salted_password,
                salt: salt,
                iterations: ScramCommon::SCRAM_DEFAULT_SALT_ITER,
            };

        return Ok(ret);
    }

    /// A program which utilizes this crate should call this function if user was found
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
    pub fn found_plaintext_password<S: ScramHashing>(pass: &[u8]) -> ScramResult<Self>
    {
        //generate salt and iterations
        let salt = ScramPassword::scram_mock_salt()?;

        let salted_password = S::derive(pass, &salt, ScramCommon::SCRAM_DEFAULT_SALT_ITER)?;

        let ret = Self::UserPasswordData
            {
                salted_hashed_password: salted_password,
                salt: salt,
                iterations: ScramCommon::SCRAM_DEFAULT_SALT_ITER,
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
    pub fn found_secret_password(salted_hashed_password: Vec<u8>, salt: Vec<u8>, iterations: u32) -> Self
    {
        return Self::UserPasswordData
            {
                salted_hashed_password: salted_hashed_password,
                salt: salt,
                iterations: iterations,
            };
    }

    /// Returns the reference to salt. Will panic! when misused.
    pub fn get_salt(&self) -> &[u8]
    {
        match *self
        {
            Self::None => panic!("misuse get_salt()"),
            Self::UserNotFound{ref salted_hashed_password, ref salt, ref iterations} => return &salt,
            Self::UserPasswordData{ref salted_hashed_password, ref salt, ref iterations} => return &salt,
        }
    }

    /// Returns the iteration count. Will panic! when misused.
    pub fn get_iterations(&self) -> u32
    {
        match *self
        {
            Self::None => panic!("misuse get_iterations()"),
            Self::UserNotFound{ref salted_hashed_password, ref salt, ref iterations} => return *iterations,
            Self::UserPasswordData{ref salted_hashed_password, ref salt, ref iterations} => return *iterations,
        }
    }

    /// Returns the salted and hashed password. Will panic! when misused.
    pub fn get_salted_hashed_password(&self) -> &[u8]
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
/// impl ScramAuthServer<ScramSha256> for AuthServer
/// {
///     fn get_password_for_user(&self, username: &str) -> ScramPassword
///     {
///         let password = match self.lookup(username)
///         {
///             Some(r) => ScramPassword::found_plaintext_password(r.as_bytes()),
///             None => ScramPassword::not_found<ScramSha256>()
///         };
/// 
///         return password;
/// 
///     }
/// }
/// ```
pub trait ScramAuthServer<S: ScramHashing>
{
    fn get_password_for_user(&self, username: &str) -> Option<ScramPassword>;
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
///     fn get_username(&self) -> &String
///     {
///         return &self.username;
///     }
/// 
///     fn get_password(&self) -> &String
///     {
///         return &self.password;
///     }
/// }
/// ```
pub trait ScramAuthClient
{
    fn get_username(&self) -> &String;
    fn get_password(&self) -> &String;
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

