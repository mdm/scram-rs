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
use std::str;
use std::marker::PhantomData;

use crate::{ScramResultServer, scram_ierror, ScramServerError, scram_ierror_map};

use super::scram_error::{ScramResult, ScramErrorCode};
use super::{scram_error, scram_error_map};
use super::scram_cb::{ServerChannelBindType, ClientChannelBindingType};
use super::scram_auth::{ScramPassword, ScramAuthServer, ScramAuthClient};
use super::scram_hashing::ScramHashing;
use super::scram_common::{ScramType, ScramCommon};
use super::scram_state::ScramState;
use super::scram_parser::*;
use super::scram::{ScramNonce, ScramResultClient};



/// # A Scram Server  
/// S: ScramHashing is picked by the program which will use this crate.
///     This library does not handle manually SCRAM types, so the developer
///     should manually parse the requested type i.e SCRAM-SHA-256 and
///     prepeare the instance correctly.  
/// A: ScramAuthServer is a callback trait for authentification. Developer
///     must attach the ScramAuthServer trait to his authentification
///     implementation.  
/// If client picks SCRAM-SHA-<any>-PLUS then the developer should 
///     also provide the data_chanbind argument with the server
///     certificate endpoint i.e native_tls::TlsStream::tls_server_end_point()  
pub struct SyncScramServer<'ss, S: ScramHashing, A: ScramAuthServer<S>>
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
    cli_chanbind: ServerChannelBindType,
    /// TLS server-endpoint certificate hash
    data_chanbind: Option<Vec<u8>>
}

impl<'ss, S: ScramHashing, A: ScramAuthServer<S>> SyncScramServer<'ss, S, A>
{
    /// Returns the supported types in format SCRAM SCRAM SCRAM
    pub 
    fn advertise_types() -> String
    {
        return ScramCommon::adrvertise(" ");
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
    /// let scram_res = ScramServer::<ScramSha256, AuthServer>::new(&serv, None, nonce, scramtype);
    /// ```
    pub 
    fn new(
        scram_auth_serv: &'ss A,
        data_chanbind: Option<Vec<u8>>, 
        scram_nonce: ScramNonce, 
        st: &'ss ScramType
    ) -> ScramResult<SyncScramServer<'ss, S, A>>
    {
        if st.scram_chan_bind == true && data_chanbind.is_none() == true
        {
            scram_ierror!(
                ScramErrorCode::ExternalError,
                "scram: '{}' requires the data_chanbind to be set",
                st
            );
        }

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
                cli_chanbind: ServerChannelBindType::n(),
                data_chanbind: data_chanbind,
            };

        return Ok(res);
    }

    /// Exposing the username privided by the client. Can be used to form a
    ///     log message. On early stages before client sends username, it is
    ///     not availabel.
    /// 
    /// # Returns
    /// 
    /// * [Option]
    ///     - `Some` with ref to username [String]
    ///     - `None` if not yet available
    pub 
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
    /// * ScramResult<[ScramParse]> the response will be encoded to UTF-8
    pub 
    fn parse_response_base64<T>(&mut self, input: T) -> ScramResultServer
    where T: AsRef<[u8]>
    {
        let decoded = 
            match base64::decode(input)
                .map_err(|e| 
                    scram_error_map!(ScramErrorCode::MalformedScramMsg, ScramServerError::InvalidEncoding,
                        "base64 decoding of client response failed with error, '{}'", e)
                )
            {
                Ok(r) => r,
                Err(e) => return ScramResultServer::Error(e)
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
    /// * ScramResult<[ScramParse]> the response will be encoded to UTF-8 depending on
    /// argument `to_base` 
    #[inline]
    pub 
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
                        self.data_chanbind.as_ref()
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
                    base64::decode(proof)
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

                let output = ["v=", &base64::encode(&server_signature)].concat();

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

/// # A Scram Client  
/// S: ScramHashing a developer should manually preprogram the ScramHashing
///     for every supported by their's program types of auth.  
/// A: ScramAuthClient a developes should attach a ScramAuthClient trait to
///     his implementation where the username and password are stored or
///     implement one.  
/// 
/// If a developer which to use a channel bind then developer should find
///     out how to extract endpoint certificate from his TLS connection.
///     i.e native_tls::TlsStream::tls_server_end_point()  
pub struct SyncScramClient<'sc, S: ScramHashing, A: ScramAuthClient>
{
    /// A hasher picked
    hasher: PhantomData<S>,
    /// A authentification callback
    auth: &'sc A,
    /// A client generated/picked nonce (base64)
    client_nonce: String,
    /// A current state step
    state: ScramState,
    /// A type of the channel bind [ClientChannelBindingType]
    chanbind: ClientChannelBindingType,
}

impl<'sc, S: ScramHashing, A: ScramAuthClient> SyncScramClient<'sc, S, A>
{
    /// Creates a new client instance and sets every field to default state
    /// 
    /// # Arguments
    /// 
    /// * `scram_auth_cli` - an authentification instance which implements [ScramAuthClient]
    /// 
    /// * `scram_nonce` - a client scram nonce [ScramNonce]
    /// 
    /// * `chan_bind_type` - picks the channel bound [ClientChannelBindingType]. It is
    ///                     responsibility of the developer to correctly set the chan binding
    ///                     type.
    /// 
    /// # Examples
    /// 
    /// ```
    /// let cbt = ClientChannelBindingType::without_chan_binding();
    ///
    /// let ac = AuthClient::new(username, password);
    /// let nonce = ScramNonce::Plain(&client_nonce_dec);
    ///
    /// let scram_res = SyncScramClient::<ScramSha256, AuthClient>::new(&ac, nonce, cbt);
    /// ```
    pub 
    fn new(
        scram_auth_cli: &'sc A, 
        scram_nonce: ScramNonce, 
        chan_bind_type: ClientChannelBindingType
    ) -> ScramResult<SyncScramClient<'sc, S, A>>
    {
        return Ok(
            Self
            {
                hasher: PhantomData,
                auth: scram_auth_cli,
                client_nonce: scram_nonce.get_nonce()?,
                state: ScramState::InitClient,
                chanbind: chan_bind_type,
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
    /// * ScramResult<[ScramParse]> the response will be encoded to UTF-8 
    pub 
    fn parse_response_base64<T: AsRef<[u8]>>(&mut self, input: T) -> ScramResult<ScramResultClient>
    {
        let decoded = 
            base64::decode(input)
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
    /// * ScramResult<[ScramParse]> the response will be encoded to UTF-8 depending on
    /// argument `to_base64`
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
                    base64::encode(
                        [
                            self.chanbind.convert2header().as_bytes(), 
                            self.chanbind.convert2data()
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
                        &base64::encode(ScramDataParser::xor_arrays(&client_key, &client_signature)?)
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


#[test]
fn scram_sha256_server() 
{ 
    use std::time::Instant;
    use super::scram_hashing::{ScramSha256};
    use super::scram_auth::ScramAuthServer;

    struct AuthServer
    {

    }

    impl ScramAuthServer<ScramSha256> for AuthServer
    {
        fn get_password_for_user(&self, _username: &str) -> ScramResult<ScramPassword>
        {
            let password = "pencil";
            let salt = b"[m\x99h\x9d\x125\x8e\xec\xa0K\x14\x126\xfa\x81".to_vec();
            let iterations = NonZeroU32::new(4096).unwrap();

            return
                Ok(
                    ScramPassword::found_secret_password(
                        ScramSha256::derive(password.as_bytes(), &salt, iterations).unwrap(),
                        base64::encode(salt), 
                        iterations,
                        None
                    )
                );          
        }
    }

    impl AuthServer
    {
        pub fn new() -> Self
        {
            return Self{};
        }
    }


    let _username = "user";
    let _password = "pencil";
    let client_nonce = "rOprNGfwEbeRWgbNEkqO";
    let _client_nonce_dec = base64::decode(client_nonce).unwrap();
    let client_init = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
    let server_init = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    let server_nonce = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    let _server_nonce_dec = b"\x86\xf6\x03\xa5e\x1a\xd9\x16\x93\x08\x07\xee\xc4R%\x8e\x13e\x16M".to_vec();
    let client_final = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    let server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
    
    let _start = Instant::now();

    let serv = AuthServer::new();
    let nonce = ScramNonce::Base64(server_nonce);
   
    let scramtype = ScramCommon::get_scramtype("SCRAM-SHA-256").unwrap();
    let scram_res = 
        SyncScramServer::<ScramSha256, AuthServer>::new(&serv, None, nonce, scramtype);
    assert_eq!(scram_res.is_ok(), true);

    let mut scram = scram_res.unwrap();

    let start = Instant::now();
    let resp_res = scram.parse_response(client_init);

    assert_eq!(resp_res.is_ok(), true);

    let resp = resp_res.get_raw_output();
    assert_eq!( resp, server_init ); 

    let resp_res = scram.parse_response(client_final);
    if resp_res.is_err() == true
    {
        println!("{}", resp_res.err().unwrap());
        assert_eq!(false, true);
        return;
    }
    
    let el = start.elapsed();
    println!("took: {:?}", el);

    let resp = resp_res.get_raw_output();
    assert_eq!( resp, server_final ); 
}

#[test]
fn scram_sha256_works() 
{ 
    use std::time::Instant;
    use super::scram_hashing::ScramSha256;
    use super::scram_auth::ScramAuthClient;
    use super::scram_auth::ScramKey;

    struct AuthClient
    {
        username: String,
        password: String,
        key: ScramKey,
    }

    impl ScramAuthClient for AuthClient
    {
        fn get_username(&self) -> &str
        {
            return &self.username;
        }

        fn get_password(&self) -> &str
        {
            return &self.password;
        }

        fn get_scram_keys(&self) -> &crate::ScramKey 
        {
            return &self.key;
        }
    }

    impl AuthClient
    {
        pub fn new(u: &'static str, p: &'static str) -> Self
        {
            return AuthClient{username: u.to_string(), password: p.to_string(), key: ScramKey::new()};
        }
    }

    let username = "user";
    let password = "pencil";
    let client_nonce = "rOprNGfwEbeRWgbNEkqO";
    let client_nonce_dec = base64::decode(client_nonce).unwrap();
    let client_init = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
    let server_init = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    let _server_nonce = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
    let _server_nonce_dec = b"\x86\xf6\x03\xa5e\x1a\xd9\x16\x93\x08\x07\xee\xc4R%\x8e\x13e\x16M";
    let client_final = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
    let server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
    
    let start = Instant::now();

    let cbt = ClientChannelBindingType::without_chan_binding();

    let ac = AuthClient::new(username, password);
    let nonce = ScramNonce::Plain(&client_nonce_dec);

    let scram_res = 
        SyncScramClient::<ScramSha256, AuthClient>::new(&ac, nonce, cbt);
    assert_eq!(scram_res.is_ok(), true);

    let mut scram = scram_res.unwrap();
    
    let init = scram.init_client();
    assert_eq!( init.get_output().unwrap(), client_init ); 

    let resp_res = scram.parse_response(server_init);
    assert_eq!(resp_res.is_ok(), true);

    let resp = resp_res.unwrap().unwrap_output().unwrap();
    assert_eq!( resp.as_str(), client_final ); 

    let res = scram.parse_response(server_final);
    
    let el = start.elapsed();
    println!("took: {:?}", el);

    assert_eq!(res.is_ok(), true, "{}", res.err().unwrap());

    assert_eq!(scram.is_completed(), true);
}

#[test]
fn scram_incorrect_test()
{
    use std::time::Instant;
    let server_init = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
    
    let start = Instant::now();
        let res = ScramDataParser::from_raw(&server_init, &ScramState::WaitForServInitMsg);
    let el = start.elapsed();
    println!("took: {:?}", el);

    assert_eq!(res.is_ok(), true);

    return;
} 
