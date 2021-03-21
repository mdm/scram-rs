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

use std::fmt;
use std::num;

pub struct ScramRuntimeError 
{
    err_code: ScramErrorCode,
    message: String,
}

impl ScramRuntimeError
{
    pub fn new(err_code: ScramErrorCode, msg: String) -> Self
    {
        return ScramRuntimeError{err_code: err_code, message: msg};
    }
}

impl fmt::Display for ScramRuntimeError 
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        write!(f, "scram: {}, {}", self.err_code, self.message)
    }
}
impl fmt::Debug for ScramRuntimeError 
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        write!(f, "scram: {}, {}", self.err_code, self.message)
    }
}


pub enum ScramErrorCode
{
    InternalError,
    VerificationError,
    ExternalError,
    MalformedScramMsg,
    FeatureNotSupported,
    ProtocolViolation,
}

impl fmt::Display for ScramErrorCode 
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        match *self 
        {
            Self::InternalError => write!(f, "Internal Server Error"),
            Self::VerificationError => write!(f, "Data Verification Error"),
            Self::ExternalError => write!(f, "External Server Error"),
            Self::MalformedScramMsg => write!(f, "Malformed Scram Message"),
            Self::FeatureNotSupported => write!(f, "Feature is not supported"),
            Self::ProtocolViolation => write!(f, "Protocol Violation"),
        }
    }
}

pub type ScramResult<T> = Result<T, ScramRuntimeError>;

/*impl From<base64::DecodeError> for ScramRuntimeError
{
    fn from(err: base64::DecodeError) -> ScramRuntimeError 
    {
        ScramRuntimeError::new(ScramErrorCode::ExternalError, format!("{}", err))
    }
}*/

/*impl From<num::ParseIntError> for ScramRuntimeError
{
    fn from(err: num::ParseIntError) -> ScramRuntimeError
    {
        ScramRuntimeError::new(ScramErrorCode::MalformedScramMsg, format!("{}", err))
    }
}*/

#[macro_export]
macro_rules! scram_error 
{
    ($src:expr,$($arg:tt)*) => (
        return std::result::Result::Err(ScramRuntimeError::new($src, format!($($arg)*)))
    )
}

#[macro_export]
macro_rules! scram_error_map
{
    ($src:expr,$($arg:tt)*) => (
        ScramRuntimeError::new($src, format!($($arg)*))
    )
}
