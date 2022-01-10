/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov, RELKOM s.r.o
 * Copyright (C) 2021-2022  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::fmt;

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

/// Error code
pub enum ScramErrorCode
{
    /// Error happened inside lib
    InternalError,

    /// Error during verification of proof or other value
    VerificationError,

    /// Error which occurs outside of the lib
    ExternalError,

    /// Error due malformed SCRAM message
    MalformedScramMsg,

    /// Error which occure when unsupported options are included in received msg
    FeatureNotSupported,

    /// Error due to protocol violation
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
