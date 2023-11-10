/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::num::NonZeroU32;
use std::str;
use std::marker::PhantomData;

use base64::Engine;
use base64::engine::general_purpose;

use crate::scram_cbh::ScramCbHelper;
pub use crate::scram_dyn::ScramServerDyn;
use crate::{scram_ierror, scram_ierror_map};

use super::scram_error::{ScramResult, ScramErrorCode};
use super::scram_cb::ChannelBindType;
use super::scram_auth::ScramAuthClient;
use super::scram_hashing::ScramHashing;
use super::scram_common::ScramCommon;
use super::scram_state::ScramState;
use super::scram_parser::*;
use super::scram::{ScramNonce, ScramResultClient};

/// # A Scram Client  
/// S: ScramHashing a developer should manually preprogram the ScramHashing
///     for every supported by their's program types of auth.  
/// A: ScramAuthClient a developes should attach a ScramAuthClient trait to
///     his implementation where the username and password are stored or
///     implement one.  
/// 
/// If code which uses this crate supports channel binding then the code uses
///     this crate should find out how to extract endpoint certificate from 
///     TLS connection.
///     i.e native_tls::TlsStream::tls_server_end_point()  
pub struct SyncScramClient<'sc, S: ScramHashing, A: ScramAuthClient, B: ScramCbHelper>
{
    /// A hasher picked
    hasher: PhantomData<S>,
    /// A authentification callback
    auth: &'sc A,
    /// A client generated/picked nonce (base64)
    client_nonce: String,
    /// A current state step
    state: ScramState,
    /// A type of the channel bind [ChannelBindType]
    chanbind: ChannelBindType,
    /// A callback to support channel bind mechanism
    chanbind_helper: &'sc B,
}

impl<'sc, S: ScramHashing, A: ScramAuthClient, B: ScramCbHelper> SyncScramClient<'sc, S, A, B>
{
    /// Creates a new client instance and sets every field to default state
    /// 
    /// # Arguments
    /// 
    /// * `scram_auth_cli` - an authentification instance which implements [ScramAuthClient]
    /// 
    /// * `scram_nonce` - a client scram nonce [ScramNonce]
    /// 
    /// * `chan_bind_type` - picks the channel bound [ChannelBindType]. It is
    ///                     responsibility of the developer to correctly set the chan binding
    ///                     type.
    /// 
    /// * `chan_bind_helper` - a data type which implements a traint [ScramCbHelper] which
    ///                 contains functions for realization which are designed to provide the
    ///                 channel bind data to the `SCRAM` crate.
    /// 
    /// # Examples
    /// 
    /// ```
    /// let cbt = ChannelBindType::None;
    ///
    /// let ac = AuthClient::new(username, password);
    /// let nonce = ScramNonce::Plain(&client_nonce_dec);
    ///
    /// let scram_res = SyncScramClient::<ScramSha256, AuthClient, AuthClient>::new(&ac, nonce, cbt, &ac);
    /// ```
    pub 
    fn new(
        scram_auth_cli: &'sc A, 
        scram_nonce: ScramNonce, 
        chan_bind_type: ChannelBindType,
        chan_bind_helper: &'sc B,
    ) -> ScramResult<SyncScramClient<'sc, S, A, B>>
    {
        return Ok(
            Self
            {
                hasher: PhantomData,
                auth: scram_auth_cli,
                client_nonce: scram_nonce.get_nonce()?,
                state: ScramState::InitClient,
                chanbind: chan_bind_type,
                chanbind_helper: chan_bind_helper,
            }
        );
    }

    /// Checks if the client authentification was completed successfully.
    pub 
    fn is_completed(&self) -> bool
    {
        match self.state
        {
            ScramState::Completed => return true,
            _ => return false,
        }
    }

    /// Initializes the SCRAM negoatiation from client
    /// 
    /// # Arguments
    /// 
    /// * `to_base64` - when set to true, the generated response will be encoded to
    ///                 base64.  
    /// 
    /// # Returns
    /// * base64 encoded or plain string with formed message
    pub 
    fn init_client(&mut self) -> ScramResultClient
    {            
        let compiled = 
            [
                self.chanbind.convert2header(),
                "n=", self.auth.get_username(),
                ",r=", self.client_nonce.as_str(),
            ].concat();
        
        self.state = ScramState::WaitForServInitMsg;     
        
        return ScramResultClient::Output(compiled);
    }

    /// Decodes the response from server which is in base64 encoded and performes parsing
    /// and result computation.
    ///
    /// # Arguments
    ///
    /// * `input` - a base64 encoded response from server
    /// 
    /// # Returns
    /// 
    /// * The [Result] is returned as alias [ScramResult].
    /// 
    /// - [Result::Ok] is returned with [ScramResultClient] which contains a hint how to
    ///     act on the next step.
    /// 
    /// - [Result::Err] is returned in case of error.
    pub 
    fn parse_response_base64<T: AsRef<[u8]>>(&mut self, input: T) -> ScramResult<ScramResultClient>
    {
        let decoded = 
            general_purpose::STANDARD.decode(input)
                .map_err(|e| 
                    scram_ierror_map!(
                        ScramErrorCode::MalformedScramMsg, 
                        "base64 decode server response failed, '{}'", e
                    )
                )?;

        let dec_utf8 = 
            str::from_utf8(&decoded)
                .map_err(|e| 
                    scram_ierror_map!(
                        ScramErrorCode::MalformedScramMsg, 
                        "base64 decoded response contains invalid UTF-8 seq, '{}'", e
                    )
                )?;

        return self.parse_response(dec_utf8);
    }

    /// Performes parsing of the response from server and result computation.  
    /// It is assumed that resp is UTF-8 valid sequences
    /// 
    /// # Arguments
    /// 
    /// * `resp` - A response from client as ref str.
    /// 
    /// * `to_base64` - if set to true, will encode response into base64.
    /// 
    /// # Returns
    /// 
    /// * The [Result] is returned as alias [ScramResult].
    /// 
    /// - [Result::Ok] is returned with [ScramResultClient] which contains a hint how to
    ///     act on the next step.
    /// 
    /// - [Result::Err] is returned in case of error.
    pub 
    fn parse_response(&mut self, resp: &str) -> ScramResult<ScramResultClient>
    {
        let parsed_resp = ScramDataParser::from_raw(&resp, &self.state)?;

        match parsed_resp
        {
            ScramData::CmsgInitial{..} =>
            {
                panic!("scram: client can not handle state: {}", parsed_resp);
            },
            // Client sends response to server after intial message
            ScramData::SmsgInitial{nonce, salt, itrcnt} => 
            {
                //validate iterations
                if itrcnt == 0 || itrcnt > ScramCommon::SCRAM_MAX_ITERS
                {
                    scram_ierror!(
                        ScramErrorCode::InternalError, 
                        "iterations count is not appropriate: i='{}'", 
                        itrcnt
                    );
                }

                //todo channel bind things SASL 
                let cb_data = 
                    general_purpose::STANDARD.encode(
                        [
                            self.chanbind.convert2header().as_bytes(), 
                            self.chanbind.get_cb_data_raw(self.chanbind_helper)?.as_slice(),
                        ].concat()
                    );

                let client_final_message_bare = ["c=", &cb_data, ",r=", nonce].concat();

                let authmsg = 
                    [
                        "n=", self.auth.get_username(),
                        ",r=", self.client_nonce.as_str(), 
                        ",", resp,
                        ",", client_final_message_bare.as_str()
                    ].concat();

                let keys = self.auth.get_scram_keys();
                
                let salted_password = 
                    S::derive(self.auth.get_password().as_bytes(), &salt, NonZeroU32::new(itrcnt).unwrap())?;
                let client_key = S::hmac(keys.get_clinet_key(), &salted_password)?;
                let server_key = S::hmac(keys.get_server_key(), &salted_password)?;


                let stored_key = S::hash(&client_key);
                let client_signature = S::hmac(authmsg.as_bytes(), &stored_key)?;
                let server_signature = S::hmac(authmsg.as_bytes(), &server_key)?;
                
                let client_response = 
                    [
                        &client_final_message_bare,
                        ",p=",
                        &general_purpose::STANDARD.encode(ScramDataParser::xor_arrays(&client_key, &client_signature)?)
                    ].concat();
                

                self.state = ScramState::WaitForServFinalMsg{server_signature: server_signature};
                
                return Ok(ScramResultClient::Output(client_response));
            },
            ScramData::CmsgFinalMessage{..} =>
            {
                panic!("scram: client can not handle state: {}", parsed_resp);
            },
            ScramData::SmsgFinalMessage{verifier, server_verifier} =>
            {
                if &verifier == server_verifier
                {
                    self.state = ScramState::Completed;

                    return Ok(ScramResultClient::Completed);
                }
                else
                {
                    scram_ierror!(
                        ScramErrorCode::VerificationError,
                        "state: '{}', server signature mismatch, server sig: '{:x?}', local: {:x?}",
                        self.state, server_verifier, verifier
                    );
                }

            }
        }
    }
}
