/*-
* RsScram
* Copyright (C) 2021  Aleksandr Morozov
* 
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Affero General Public License for more details.
* 
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

use super::scram_error::{ScramResult, ScramRuntimeError, ScramErrorCode};
use super::{scram_error, scram_error_map};

use super::scram_common::ScramCommon;
use super::scram_hashing::ScramHashing;


pub enum ScramPassword
{
    /// Default state for initialization
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
    pub fn default() -> Self
    {
        return Self::None;
    }

    fn scram_mock_salt() -> ScramResult<Vec<u8>>
    {
        //generate mock auth nonce (todo: to statically created)
        let mock_auth_nonce = ScramCommon::pg_random(ScramCommon::MOCK_AUTH_NONCE_LEN)?;

        return Ok(mock_auth_nonce);
    }

    pub fn not_found<S: ScramHashing>() -> ScramResult<Self>
    {
        // generate fake data
        let salt = ScramPassword::scram_mock_salt()?;

        let password_raw = ScramCommon::pg_random(ScramCommon::MOCK_AUTH_NONCE_LEN)?;

        let salted_password = S::derive(&password_raw, &salt, ScramCommon::SCRAM_DEFAULT_SALT_ITER)?;

        let ret = Self::UserNotFound
            {
                salted_hashed_password: salted_password,
                salt: salt,
                iterations: ScramCommon::SCRAM_DEFAULT_SALT_ITER,
            };

        return Ok(ret);
    }

    /// Plaintext password was found, needs hashing.
    pub fn found_plaintext_password<S: ScramHashing>(pass: &[u8], ) -> ScramResult<Self>
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

    /// a SHA-? hashed password, salt and iterations
    pub fn found_secret_password(salted_hashed_password: Vec<u8>, salt: Vec<u8>, iterations: u32) -> Self
    {
        return Self::UserPasswordData
            {
                salted_hashed_password: salted_hashed_password,
                salt: salt,
                iterations: iterations,
            };
    }

    pub fn get_salt(&self) -> &[u8]
    {
        match *self
        {
            Self::None => panic!("misuse get_salt()"),
            Self::UserNotFound{ref salted_hashed_password, ref salt, ref iterations} => return &salt,
            Self::UserPasswordData{ref salted_hashed_password, ref salt, ref iterations} => return &salt,
        }
    }

    pub fn get_iterations(&self) -> u32
    {
        match *self
        {
            Self::None => panic!("misuse get_iterations()"),
            Self::UserNotFound{ref salted_hashed_password, ref salt, ref iterations} => return *iterations,
            Self::UserPasswordData{ref salted_hashed_password, ref salt, ref iterations} => return *iterations,
        }
    }

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

/// A authentification backend which is behind the SCRAM lib
/// A lib use should do the realization of this trait
///     to access the auth database
pub trait ScramAuthServer
{
    fn get_password_for_user(&self, username: &str) -> ScramPassword;
}

/// A authentification backend which is behind the SCRAM lib
///     to access auth data username:password
pub trait ScramAuthClient
{
    fn get_username(&self) -> &String;
    fn get_password(&self) -> &String;
}

/*pub enum ScramAuth
{
    Client(dyn ScramAuthClient),
    Server(dyn ScramAuthServer),
}

impl ScramAuth
{
    pub fn get_username(&self) -> &String
    {
        match *self
        {
            Self::Client(ref s) => s.get_username(),
            Self::Server(_) => panic!("scram: ScramAuth get_username misuse"),
        }
    }

    pub fn get_password(&self) -> &String
    {
        match *self
        {
            Self::Client(ref s) => s.get_password(),
            Self::Server(_) => panic!("scram: ScramAuth get_password misuse"),
        }
    }

    pub fn get_password_for_user(&self, username: &String) -> ScramPassword
    {
        match *self
        {
            Self::Client(_) => panic!("scram: ScramAuth get_password_for_user misuse"),
            Self::Server(ref s) => s.get_password_for_user(username),
        }
    }
}*/
