/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::str;
use std::marker::PhantomData;

use base64::Engine;
use base64::engine::general_purpose;
pub use super::scram_dyn::ScramServerDyn;
use super::scram_cbh::ScramCbHelper;
use super::{ScramResultServer, ScramServerError};
use super::scram_error::{ScramResult, ScramErrorCode};
use super::{scram_error, scram_error_map};
use super::scram_cb::ChannelBindType;
use super::scram_auth::{ScramPassword, ScramAuthServer};
use super::scram_hashing::ScramHashing;
use super::scram_common::{ScramType, ScramCommon};
use super::scram_state::ScramState;
use super::scram_parser::*;
use super::scram::ScramNonce;



/// # A Scram Server  
/// S: ScramHashing is picked by the program which will use this crate.
///     This library does not handle manually SCRAM types, so the developer
///     should manually parse the requested type i.e SCRAM-SHA-256 and
///     prepeare the instance correctly.  
/// A: ScramAuthServer is a callback trait for authentification. Developer
///     must attach the ScramAuthServer trait to his authentification
///     implementation.  
/// If client picks SCRAM-SHA-\<any\>-PLUS then the developer should 
///     also provide the data_chanbind argument with the server
///     certificate endpoint i.e native_tls::TlsStream::tls_server_end_point()  
#[derive(Debug)]
pub struct SyncScramServer<'ss, S: ScramHashing, A: ScramAuthServer<S>, B: ScramCbHelper>
{
    /// The hasher which will be used: SHA-1 SHA-256
    hasher: PhantomData<S>,
    /// The Auth backend which handles user search
    auth: &'ss A,
    /// The current instance type
    st: &'ss ScramType,
    /// username n=
    username: Option<String>,
    /// Returned password with status found/notfound
    sp: ScramPassword,
    /// Generated server nonce
    server_nonce: String,
    /// Current scrum state
    state: ScramState,
    /// Received channel binding opt from client
    cli_chanbind: ChannelBindType,
    /// A callback to support channel bind mechanism
    chanbind_helper: &'ss B,
}

impl<'ss, S: ScramHashing + 'ss, A: ScramAuthServer<S>, B: ScramCbHelper> ScramServerDyn 
for SyncScramServer<'ss, S, A, B>
{

    /// Exposing the username privided by the client. Can be used to form a
    ///     log message. On early stages before client sends username, it is
    ///     not availabel.
    /// 
    /// # Returns
    /// 
    /// * [Option]
    ///     - `Some` with ref to username [String]
    ///     - `None` if not yet available 
    fn get_auth_username(&self) -> Option<&String>
    {
        return self.username.as_ref();
    }

    /// Decodes the input from base64 and performes parsing and result computation.  
    /// 
    /// # Arguments
    /// 
    /// * `input` - A response from client.
    /// 
    /// # Returns
    /// 
    /// * The [ScramResultServer] is returned with the result. 
    fn parse_response_base64(&mut self, input: &[u8]) -> ScramResultServer
    {
        let decoded = 
            match general_purpose::STANDARD.decode(input)
                .map_err(|e| 
                    scram_error_map!(ScramErrorCode::MalformedScramMsg, ScramServerError::InvalidEncoding,
                        "base64 decoding of client response failed with error, '{}'", e)
                )
                .map_err(|e| ScramResultServer::Error(e))
            {
                Ok(r) => r,
                Err(e) => return e
            };
                

        let dec_utf8 = 
            match str::from_utf8(&decoded)
                    .map_err(|e| 
                        scram_error_map!(
                            ScramErrorCode::MalformedScramMsg, ScramServerError::InvalidEncoding,
                            "base64 decoded response contains invalid UTF-8 seq, '{}'", e
                        )
                    )
            {
                Ok(r) => r,
                Err(e) => return ScramResultServer::Error(e)
            };

        return self.parse_response(dec_utf8);
    }

    /// Performes parsing of the response from client and result computation.  
    /// It is assumed that resp is UTF-8 valid sequences
    /// 
    /// # Arguments
    /// 
    /// * `resp` - A response from client as ref str.
    /// 
    /// * `to_base` - if set to true, will encode response into base64.
    /// 
    /// # Returns
    /// 
    /// * The [ScramResultServer] is returned with the result.
    fn parse_response(&mut self, resp: &str) -> ScramResultServer
    {
        match self.parse_response_internal(resp)
        {
            Ok(r) =>
            {
                if self.state == ScramState::Completed
                {
                    return ScramResultServer::Final(r);
                }
                else
                {
                    return ScramResultServer::Data(r);
                }
            },
            Err(e) =>
            {
                return ScramResultServer::Error(e);
            }
        }
    }
}

impl<'ss, S: ScramHashing + 'ss, A: ScramAuthServer<S>, B: ScramCbHelper> SyncScramServer<'ss, S, A, B>
{
    /// Returns the supported types in format SCRAM SCRAM SCRAM
    pub 
    fn advertise_types<T>(sep: T) -> String
    where
        T: AsRef<str>,
    {
        return ScramCommon::adrvertise(sep);
    }


    /// Creates new instance of the SyncScramServer with lifetime 'ss
    /// 
    /// # Arguments
    /// 
    /// * `scram_auth_serv` - A reference to the instance which implements
    /// [ScramAuthServer]
    /// 
    /// * `data_chanbind` - A channel binding data TLS Endpoint Cert Hash
    /// 
    /// * `chan_bind_helper` - An implemented trait [ScramCbHelper] which should provide 
    ///                 crate with all necessary data for channel bind.
    /// 
    /// * `scram_nonce` - A Scram Nonce type
    /// 
    /// * `st` - A type of the scram picked by name from table [super::scram_common::SCRAM_TYPES]
    /// 
    /// # Examples
    /// ```
    /// let serv = AuthServer::new();
    /// let nonce = ScramNonce::Base64(server_nonce);
    ///
    /// let scramtype = ScramCommon::get_scramtype("SCRAM-SHA-256").unwrap();
    /// let scram_res = ScramServer::<ScramSha256, AuthServer, AuthServer>::new(&serv, &serv, nonce, scramtype);
    /// ```
    pub 
    fn new(
        scram_auth_serv: &'ss A,
        chan_bind_helper: &'ss B,
        scram_nonce: ScramNonce, 
        st: &'ss ScramType
    ) -> ScramResult<SyncScramServer<'ss, S, A, B>>
    {

        let res = 
            Self
            {
                hasher: PhantomData,
                auth: scram_auth_serv,
                st: st,
                username: None,
                sp: ScramPassword::default(),
                server_nonce: scram_nonce.get_nonce()?,
                state: ScramState::WaitForClientInitalMsg,
                cli_chanbind: ChannelBindType::n(),
                chanbind_helper: chan_bind_helper,
            };

        return Ok(res);
    }

    pub 
    fn make_dyn(self) -> Box<dyn ScramServerDyn + 'ss>//ScramServerDynHolder<'ss>
    {
        return Box::new(self);//ScramServerDynHolder::new(Box::new(self));
    }
 
    fn parse_response_internal(&mut self, resp: &str) -> ScramResult<String>
    {
        let parsed_resp = ScramDataParser::from_raw(resp, &self.state)?;

        match parsed_resp
        {
            // Initial message from client
            ScramData::CmsgInitial{chan_bind, user, nonce} =>
            {
                //channel bind test
                chan_bind.server_initial_verify_client_cb(self.st)?;

                //authID is not supported

                //get user
                let sp = 
                    self.auth.get_password_for_user(user)?;

                /*if sp.is_ok() == false
                {
                    scram_error!(ScramErrorCode::ExternalError,
                        "authentification server failed for unknown reason");
                }*/

                // form output
                let output = 
                    [
                        "r=", nonce, &self.server_nonce, 
                        ",s=", sp.get_salt_base64(), 
                        ",i=", &sp.get_iterations().to_string()
                    ].concat();

                // update state
                self.cli_chanbind = chan_bind;
                self.username = Some(user.to_string());
                self.sp = sp;
                self.state = ScramState::WaitForClientFinalMsg{client_nonce: String::from(nonce)};

                return Ok(output);
            },
            ScramData::SmsgInitial{..} => 
            {
                panic!("server can not handle state: {}", parsed_resp);
            },
            //final message from client (STEP 2)
            ScramData::CmsgFinalMessage{chanbinding, finalnonce, proof, client_nonce} =>
            {
                // verify channel bind
                self.cli_chanbind
                    .server_final_verify_client_cb(
                        self.st, 
                        chanbinding,
                        self.chanbind_helper
                    )?;

                let nonce = 
                    [client_nonce.as_str(), self.server_nonce.as_str()].concat();

                // verify nonce
                if finalnonce != nonce.as_str()
                {
                    scram_error!(
                        ScramErrorCode::VerificationError,
                        ScramServerError::OtherError,
                        "received invalid nonce username: '{}' rcvn: '{}' have: '{}'", 
                        self.username.as_ref().map_or("-missing-", |v| v.as_str()), finalnonce, client_nonce
                    );
                }

                /*let cb_data = base64::encode(
                    [
                        self.cli_chanbind.convert2header(), 
                        self.cli_chanbind.convert2data()
                    ].concat());*/
    
                //base64 config
                
                let client_final_without_proof = 
                    ["c=", chanbinding, ",r=", &nonce].concat();

                let client_first_bare = 
                    ["n=", self.username.as_ref().unwrap(), ",r=", client_nonce].concat();

                let server_first = 
                    [
                        "r=", &nonce, 
                        ",s=", self.sp.get_salt_base64(),
                        ",i=", &self.sp.get_iterations().to_string(),
                    ].concat();

                let authmsg = 
                    [
                        &client_first_bare,
                        ",",
                        &server_first,
                        ",",
                        &client_final_without_proof,
                    ].concat();
                
                let keys = self.sp.get_scram_keys();
                //b"Client Key"
                //b"Server Key"
                
                let client_key = S::hmac(keys.get_clinet_key(), &self.sp.get_salted_hashed_password())?;
                let server_key = S::hmac(keys.get_server_key(), &self.sp.get_salted_hashed_password())?;
                let stored_key = S::hash(&client_key);
                let client_signature = S::hmac(authmsg.as_bytes(), &stored_key)?;
                let server_signature = S::hmac(authmsg.as_bytes(), &server_key)?;

                let calc_client_proof = ScramDataParser::xor_arrays(&client_key, &client_signature)?;

                // verify proof
                let recv_decoded_proof = 
                    general_purpose::STANDARD.decode(proof)
                        .map_err(|e| 
                            scram_error_map!(
                                ScramErrorCode::MalformedScramMsg, 
                                ScramServerError::InvalidEncoding,
                                "base64 decode client proof failed, {}", e
                            )
                        )?;

                if calc_client_proof != recv_decoded_proof
                {
                    scram_error!(ScramErrorCode::VerificationError, ScramServerError::InvalidProof,
                        "received invalid proof from client, username: '{}'", 
                        self.username.as_ref().map_or("-missing-", |v| v.as_str()));
                }

                let output = ["v=", &general_purpose::STANDARD.encode(&server_signature)].concat();

                // update states
                self.state = ScramState::Completed;

                return Ok(output);
            },
            ScramData::SmsgFinalMessage{..} =>
            {
                panic!("server can not handle state: {}", parsed_resp);
            }
        }
    }
}




