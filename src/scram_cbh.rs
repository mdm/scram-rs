/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use core::fmt;

use async_trait::async_trait;

use crate::{ScramResult, ScramErrorCode};

use crate::scram_ierror;

/// A trait which contains a functions that should be used on the program
/// side which utilizes this crate. Those functions should return data 
/// from your TLS crate:
/// * TLS endpoint cert hash
/// * TLS unique
/// * TLS exporter data
/// 
/// By defualt each function returns error: [ScramErrorCode::ChanBindNotImplemented]
/// 
/// Functions must return a raw data retreived form your TLS library.
pub trait ScramCbHelper: fmt::Debug
{
    /// This function returns (on success) a TLS endpoint cert data.
    /// For example from function: native_tls::TlsStream::tls_server_end_point()
    /// To indicate error, use macros: HELPER_ERROR_CLIENT or HELPER_ERROR_SERVER
    fn get_tls_server_endpoint(&self) -> ScramResult<Vec<u8>>
    {
        scram_ierror!(
            ScramErrorCode::ChanBindNotImplemented, 
            "`tls_server_endpoint` not implemented!"
        );
    }

    /// This function returns (on success) a TLS unique data.
    /// To indicate error, use macros: HELPER_ERROR_CLIENT or HELPER_ERROR_SERVER
    fn get_tls_unique(&self) -> ScramResult<Vec<u8>>
    {
        scram_ierror!(
            ScramErrorCode::ChanBindNotImplemented, 
            "`tls_unique` not implemented!"
        );
    }

    /// This function returns (on success) a TLS exporter (TLS 1.3) data.
    /// To indicate error, use macros: HELPER_ERROR_CLIENT or HELPER_ERROR_SERVER
    fn get_tls_exporter(&self) -> ScramResult<Vec<u8>>
    {
        scram_ierror!(
            ScramErrorCode::ChanBindNotImplemented, 
            "`tls_exporter` not implemented!"
        );
    }
}

/// An `async` trait which contains a functions that should be used on the program
/// side which utilizes this crate. Those functions should return data 
/// from your TLS crate:
/// * TLS endpoint cert hash
/// * TLS unique
/// * TLS exporter data
/// 
/// By defualt each function returns error: ScramErrorCode::ChanBindNotImplemented
#[async_trait]
pub trait AsyncScramCbHelper: Sync + fmt::Debug
{
    /// This function returns (on success) a TLS endpoint cert data.
    /// For example from function: native_tls::TlsStream::tls_server_end_point()
    /// To indicate error, use macros: HELPER_ERROR_CLIENT or HELPER_ERROR_SERVER
    async fn get_tls_server_endpoint(&self) -> ScramResult<Vec<u8>>
    {
        {
            scram_ierror!(
                ScramErrorCode::ChanBindNotImplemented, 
                "`tls_server_endpoint` not implemented!"
            );
        }
    }

    /// This function returns (on success) a TLS unique data.
    /// To indicate error, use macros: HELPER_ERROR_CLIENT or HELPER_ERROR_SERVER
    async fn get_tls_unique(&self) -> ScramResult<Vec<u8>>
    {
        scram_ierror!(
            ScramErrorCode::ChanBindNotImplemented, 
            "`tls_unique` not implemented!"
        );
    }

    /// This function returns (on success) a TLS exporter (TLS 1.3) data.
    /// To indicate error, use macros: HELPER_ERROR_CLIENT or HELPER_ERROR_SERVER
    async fn get_tls_exporter(&self) -> ScramResult<Vec<u8>>
    {
        scram_ierror!(
            ScramErrorCode::ChanBindNotImplemented, 
            "`tls_exporter` not implemented!"
        );
    }
}

/// Use this macro in functions of trais [ScramCbHelper], [AsyncScramCbHelper]
/// on client side in order to indicate that this type of channel bind is not supported!
#[macro_export]
macro_rules!  HELPER_UNSUP_CLIENT
{
    ($cbt:expr) => (
        $crate::scram_ierror!(
            $crate::scram_error::ScramErrorCode::ChanBindNotImplemented, 
            "`{}` not implemented!", $cbt
        );
    )
}

/// Use this macro in functions of trais [ScramCbHelper], [AsyncScramCbHelper]
/// on server side in order to indicate that this type of channel bind is not supported!
#[macro_export]
macro_rules!  HELPER_UNSUP_SERVER
{
    ($cbt:expr) => (
        $crate::scram_error!(
            $crate::scram_error::ScramErrorCode::MalformedScramMsg, 
            $crate::scram_error::ScramServerError::UnsupportedChannelBindingType,
            "`{}` unsupported channel bind type!", $cbt
        );
    )
}

/// Use this macro in functions of trais [ScramCbHelper], [AsyncScramCbHelper]
/// on client side in order to indicate that the data is not possible to retrive
#[macro_export]
macro_rules!  HELPER_ERROR_CLIENT
{
    ($cbt:expr, $($arg:tt)*) => (
        $crate::scram_ierror!(
            $crate::scram_error::ScramErrorCode::ExternalError, 
            "`{}` error: '{}'", $cbt, format!($($arg)*)
        );
    )
}

/// Use this macro in functions of trais [ScramCbHelper], [AsyncScramCbHelper]
/// on server side in order to indicate that the data is not possible to retrive
#[macro_export]
macro_rules!  HELPER_ERROR_SERVER
{
    ($cbt:expr, $($arg:tt)*) => (
        $crate::scram_error!(
            $crate::scram_error::ScramErrorCode::ExternalError, 
            $crate::scram_error::ScramServerError::OtherError,
            "`{}` error: '{}'", $cbt, format!($($arg)*)
        );
    )
}
