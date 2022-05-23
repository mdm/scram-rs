/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov, RELKOM s.r.o
 * Copyright (C) 2021-2022  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */


use std::mem;

use super::scram_error::{ScramResult, ScramErrorCode};
use super::{scram_error};
use super::scram_common::ScramCommon;

pub use super::scram_sync;
pub use super::scram_async;

/// A state encoder for Scram Client.
/// There is an internal state machine which automatically changes the
///  state. The timeout and other things must be implemented separatly.
///  The state from internal state machine is not exposed. If needed can
///  be maintained separatly.
#[derive(Debug)]
pub struct ScramResultServer
{   
    /// A response to send (raw)
    pub raw_out: String,

    /// If set to true, the last response is generated and auth
    ///  completes.
    pub completed: bool,
}

impl ScramResultServer
{
    /// Tells if auth seq completed.
    pub 
    fn is_completed(&self) -> bool
    {
        return self.completed;
    }

    /// Encodes the raw result to base64.
    pub 
    fn encode_base64(&self) -> String
    {
        return base64::encode(&self.raw_out);
    }

    /// Returns the ref [str] to raw output.
    pub 
    fn get_raw_output(&self) -> &str
    {
        return self.raw_out.as_str();
    }
}

/// A state encoder for Scram Client.
/// There is an internal state machine which automatically changes the
///  state. The timeout and other things must be implemented separatly.
///  The state from internal state machine is not exposed. If needed can
///  be maintained separatly.
#[derive(Debug)]
pub enum ScramResultClient
{
    /// A response was composed and stored in raw format
    Output( String ),

    /// Final stage, no more parsing is required, auth was successful.
    /// If auth failed an error will be thrown.
    Completed
}

impl ScramResultClient
{
    /// Tells if the current status is [ScramResultClient::Output]
    pub 
    fn is_output(&self) -> bool
    {
        return 
            mem::discriminant(self) == mem::discriminant(&ScramResultClient::Output( String::new() ));
    }

    /// Tells is current status is [ScramResultClient::Completed].
    pub 
    fn is_final(&self) -> bool
    {
        return 
            mem::discriminant(self) == mem::discriminant(&ScramResultClient::Completed);
    }

    /// Unwraps the result which should be sent to server. The result is raw and
    ///  not encoded to base64!
    /// 
    /// # Returns
    /// 
    /// * [ScramResult]
    ///     - Ok() with payload (raw output)
    ///     - Err(e) [ScramErrorCode::AuthSeqCompleted] if called on state
    ///         [ScramResultClient::Completed].
    pub 
    fn unwrap_output(self) -> ScramResult<String>
    {
        match self
        {
            ScramResultClient::Output(output) => 
                return Ok(output),
            ScramResultClient::Completed => 
                scram_error!(ScramErrorCode::AuthSeqCompleted, "completed, nothing to extract"),
        }
    }

    /// Unwraps the result which should be sent to server and returns a ref
    ///  [str]. The result is raw and not encoded to base64!
    /// 
    /// # Returns
    /// 
    /// * [ScramResult]
    ///     - Ok() with payload (raw output)
    ///     - Err(e) [ScramErrorCode::AuthSeqCompleted] if called on state
    ///         [ScramResultClient::Completed].
    pub 
    fn get_output(&self) -> ScramResult<&str>
    {
        match self
        {
            ScramResultClient::Output(output) => 
                return Ok(output.as_str()),
            ScramResultClient::Completed => 
                scram_error!(ScramErrorCode::AuthSeqCompleted, "completed, nothing to extract"),
        }
    }

    /// Encodes the output to base64.
    /// 
    /// # Returns
    /// 
    /// * [ScramResult]
    ///     - Ok() with payload (encoded to base64 output)
    ///     - Err(e) [ScramErrorCode::AuthSeqCompleted] if called on state
    ///         [ScramResultClient::Completed].
    pub 
    fn encode_output_base64(&self) -> ScramResult<String>
    {
        match self
        {
            ScramResultClient::Output(output) => 
                return Ok(base64::encode(output)),
            ScramResultClient::Completed => 
                scram_error!(ScramErrorCode::AuthSeqCompleted, "completed, nothing to extract"),
        }
    }
}

/// A SCRAM nonce initialization and customization.
/// Use implemented functions, don't use enum fields directly.
pub enum ScramNonce<'sn>
{
    /// Nonce is not provided by user, autogenerate
    None,

    /// A nonce is encoded as plain text 
    Plain(&'sn [u8]),

    /// A nonce is encoded as base64
    Base64(&'sn str),
}

impl<'sn> ScramNonce<'sn>
{
    /// Initialize ScramNonce so the data will be autogenerated
    pub 
    fn none() -> Self
    {
        return Self::None;
    }

    /// Initialize ScramNonce with plain data.
    pub 
    fn plain(p: &'sn [u8]) -> ScramNonce<'sn>
    {
        return Self::Plain(p);
    }

    /// Initialize ScramNonce with base64 encoded nonce. 
    pub 
    fn base64(b: &'sn str) -> ScramNonce<'sn>
    {
        return Self::Base64(b);
    }

    /// Extract Nonce
    /// Will throw error if base64 will fail to encode the provided data to base64.
    /// Will throw error if argument length is 0.
    pub 
    fn get_nonce(self) -> ScramResult<String>
    {
        match self
        {
            ScramNonce::None => 
            {
                return Ok(
                    base64::encode(
                        ScramCommon::sc_random(ScramCommon::SCRAM_RAW_NONCE_LEN)?
                    )
                );
            },
            ScramNonce::Plain(p) => 
            {
                if p.len() > ScramCommon::SCRAM_RAW_NONCE_LEN
                {
                    scram_error!(
                        ScramErrorCode::InternalError,
                        "nonce length is > {}, actual: '{}'", 
                        ScramCommon::SCRAM_RAW_NONCE_LEN, p.len()
                    );
                }

                return Ok(base64::encode(p));
            },
            ScramNonce::Base64(b) => 
            {
                if b.len() == 0
                {
                    scram_error!(ScramErrorCode::InternalError, "base64 nonce length is 0");
                }
                
                return Ok(b.to_string())
            }
        };
    }
}


