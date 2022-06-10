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
    /// Error code for internal usage
    pub err_code: ScramErrorCode,
    /// Error code for exteranl usage i.e RFC5802 errors for error 
    ///  handling on client side if no other signalling is used.
    pub err_serv: ScramServerError,
    /// Human readable message with description.
    pub message: String,
}

impl ScramRuntimeError
{
    pub 
    fn new(err_code: ScramErrorCode, err_serv: ScramServerError, msg: String) -> Self
    {
        return ScramRuntimeError{err_code: err_code, err_serv: err_serv, message: msg};
    }

    /// Converts the external error code to SCRAM protocol format.
    pub 
    fn serv_err_value(&self) -> &str 
    {
       return  
            match self.err_serv
            {
                ScramServerError::None => "e=other-error",
                ScramServerError::InvalidEncoding => "e=invalid-encoding",
                ScramServerError::ExtensionsNotSupported => "e=extensions-not-supported",
                ScramServerError::InvalidProof => "e=invalid-proof",
                ScramServerError::ChannelBindingsDontMatch => "e=channel-bindings-dont-match",
                ScramServerError::ServerDoesSupportChannelBinding => "e=server-does-support-channel-binding",
                ScramServerError::ChannelBindingNotSupported => "e=channel-binding-not-supported",
                ScramServerError::UnsupportedChannelBindingType => "e=unsupported-channel-binding-type",
                ScramServerError::UnknownUser => "e=unknown-user",
                ScramServerError::InvalidUsernameEncoding => "e=invalid-username-encoding",
                ScramServerError::NoResources => "e=no-resources",
                ScramServerError::OtherError => "e=other-error"
            };
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScramServerError
{
    /// Same as OtherError
    None,
    InvalidEncoding,

    /// unrecognized 'm' value
    ExtensionsNotSupported,
    InvalidProof,
    ChannelBindingsDontMatch,
    ServerDoesSupportChannelBinding,
    ChannelBindingNotSupported,
    UnsupportedChannelBindingType,
    /// Unused, if user was not found a mock auth is performed
    ///  and `InvalidProof` is sent.
    UnknownUser,
    InvalidUsernameEncoding,
    NoResources,

    /// For any errors that may disclose sensitive information
    OtherError
}



impl fmt::Display for ScramServerError 
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        let d = 
            match *self
            {
                Self::None => 
                    "None",
                Self::InvalidEncoding => 
                    "Invalid Encoding",
                Self::ExtensionsNotSupported => 
                    "Extension Not Supported, unrecognized 'm' value",
                Self::InvalidProof => 
                    "Invalid Proof",
                Self::ChannelBindingsDontMatch => 
                    "Channel Bindings Don't Match",
                Self::ServerDoesSupportChannelBinding => 
                    "Server Does Support Channel Binding",
                Self::ChannelBindingNotSupported => 
                    "Channel Binding Not Supported",
                Self::UnsupportedChannelBindingType => 
                    "Unsupported Channel Binding Type",
                Self::UnknownUser => 
                    "Unknown User",
                Self::InvalidUsernameEncoding => 
                    "Invalid Username Enconding",
                Self::NoResources => 
                    "No Resources",
                Self::OtherError => 
                    "Other Error"
            };

        return write!(f, "{}", d);
    }
}
impl fmt::Debug for ScramServerError 
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        let d = 
            match *self
            {
                Self::None => 
                    "None",
                Self::InvalidEncoding => 
                    "Invalid Encoding",
                Self::ExtensionsNotSupported => 
                    "Extension Not Supported, unrecognized 'm' value",
                Self::InvalidProof => 
                    "Invalid Proof",
                Self::ChannelBindingsDontMatch => 
                    "Channel Bindings Don't Match",
                Self::ServerDoesSupportChannelBinding => 
                    "Server Does Support Channel Binding",
                Self::ChannelBindingNotSupported => 
                    "Channel Binding Not Supported",
                Self::UnsupportedChannelBindingType => 
                    "Unsupported Channel Binding Type",
                Self::UnknownUser => 
                    "Unknown User",
                Self::InvalidUsernameEncoding => 
                    "Invalid Username Enconding",
                Self::NoResources => 
                    "No Resources",
                Self::OtherError => 
                    "Other Error"
            };

        return write!(f, "{}", d);
    }
}

impl From<&str> for ScramServerError
{
    fn from(value: &str) -> Self
    {
        match value
        {
            "invalid-encoding" => 
                Self::InvalidEncoding,
            "extensions-not-supported" => 
                Self::ExtensionsNotSupported,
            "invalid-proof" => 
                Self::InvalidProof,
            "channel-bindings-dont-match" => 
                Self::ChannelBindingsDontMatch,
            "server-does-support-channel-binding" => 
                Self::ServerDoesSupportChannelBinding,
            "channel-binding-not-supported" => 
                Self::ChannelBindingNotSupported,
            "unsupported-channel-binding-type" => 
                Self::UnsupportedChannelBindingType,
            "unknown-user" => 
                Self::UnknownUser,
            "invalid-username-encoding" => 
                Self::InvalidUsernameEncoding,
            "no-resources" => 
                Self::NoResources,
            "other-error" => Self::OtherError,
            _ => Self::OtherError,
        }
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

    /// Wrong call on extract result
    AuthSeqCompleted,

    /// Client side received error
    ClientSide
}

impl fmt::Display for ScramErrorCode 
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        match *self 
        {
            Self::InternalError     => write!(f, "Internal Server Error"),
            Self::VerificationError => write!(f, "Data Verification Error"),
            Self::ExternalError     => write!(f, "External Server Error"),
            Self::MalformedScramMsg => write!(f, "Malformed Scram Message"),
            Self::FeatureNotSupported => write!(f, "Feature is not supported"),
            Self::ProtocolViolation => write!(f, "Protocol Violation"),
            Self::AuthSeqCompleted  => write!(f, "Completed!"),
            Self::ClientSide        => write!(f, "Server reported error"),
        }
    }
}

pub type ScramResult<T> = Result<T, ScramRuntimeError>;

#[macro_export]
macro_rules! scram_error 
{
    ($src:expr, $serv_err:expr, $($arg:tt)*) => (
        return std::result::Result::Err($crate::ScramRuntimeError::new($src, $serv_err, format!($($arg)*)))
    )
}

#[macro_export]
macro_rules! scram_ierror 
{
    ($src:expr, $($arg:tt)*) => (
        return std::result::Result::Err($crate::ScramRuntimeError::new($src, $crate::ScramServerError::None, format!($($arg)*)))
    )
}


#[macro_export]
macro_rules! scram_ierror_map
{
    ($src:expr, $($arg:tt)*) => (
        $crate::ScramRuntimeError::new($src, $crate::ScramServerError::None, format!($($arg)*))
    )
}

#[macro_export]
macro_rules! scram_error_map
{
    ($src:expr, $serv_err:expr, $($arg:tt)*) => (
        $crate::ScramRuntimeError::new($src, $serv_err, format!($($arg)*))
    )
}

