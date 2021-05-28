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
use std::str;
use std::str::Chars;
use std::iter::Peekable;
use std::marker::PhantomData;

use super::scram_error::{ScramResult, ScramRuntimeError, ScramErrorCode};
use super::{scram_error, scram_error_map};
use super::scram_cb::{ServerChannelBindType, ClientChannelBindingType};
use super::scram_auth::{ScramPassword, ScramAuthServer, ScramAuthClient};
use super::scram_hashing::ScramHashing;
use super::scram_common::{ScramType, ScramCommon};


/// Order:
/// Client init: InitClient
/// Server init: WaitForClientInitalMsg
/// 
/// Client sends data and sets state: WaitForSevInitMsg
/// Server receives data and changes state to: WaitForClientFinalMsg
/// 
/// Client sends final response and sets state: WaitFinalStageFromServ
/// Server receives data and sends response and sets: Complete
/// 
/// Client receives and sets its state to: Complete

#[derive(PartialEq, Clone)]
enum ScramState 
{    
    /// Instance of client was created, but no comm yet initialized
    InitClient,    

    /// Client waits for the first response, after it sends initial data
    WaitForServInitMsg, 

    /// Client waits for the last response from server
    WaitForServFinalMsg{server_signature: Vec<u8>}, 

    /// Server is rready to accept first message from server
    WaitForClientInitalMsg, 

    /// Server has sent initial response to client, args: client_nonce: String
    WaitForClientFinalMsg{client_nonce: String},
    
    /// Server has sent second anser
    /// Completed: for client, 3rd response received
    /// for server, the last response was sent
    Completed,
}

impl fmt::Display for ScramState
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        match *self 
        {
            Self::InitClient                => write!(f, "InitClient"),
            Self::WaitForServInitMsg        => write!(f, "WaitForServInitMsg"),
            Self::WaitForServFinalMsg{..}   => write!(f, "WaitForServFinalMsg"),
            Self::WaitForClientInitalMsg    => write!(f, "WaitForClientInitalMsg"),
            Self::WaitForClientFinalMsg{..} => write!(f, "WaitForClientFinalMsg"),
            Self::Completed                 => write!(f, "Completed"),
        }
    }
}

impl fmt::Debug for ScramState
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        match *self 
        {
            Self::InitClient                => write!(f, "InitClient"),
            Self::WaitForServInitMsg        => write!(f, "WaitForServInitMsg"),
            Self::WaitForServFinalMsg{..}   => write!(f, "WaitForServFinalMsg"),
            Self::WaitForClientInitalMsg    => write!(f, "WaitForClientInitalMsg"),
            Self::WaitForClientFinalMsg{..} => write!(f, "WaitForClientFinalMsg"),
            Self::Completed                 => write!(f, "Completed"),
        }
    }
}

/// A returned datatype from both Server/Client parser.  
/// If [ScramParse::Output] then a response was prepared.  
/// If [ScramParse::Completed] then no other action is required.
pub enum ScramParse
{
    /// Data is prepared to be sent to Server or Client
    Output(String),

    /// Final stage, no more parsing is required
    Completed,
}

impl ScramParse
{
    /// Is current instance is Output(...)
    pub fn is_output(&self) -> bool
    {
        match *self
        {
            ScramParse::Output(_) => return true,
            ScramParse::Completed => return false
        }
    }

    /// Is current instance is Completed
    pub fn is_final(&self) -> bool
    {
        match *self
        {
            ScramParse::Output(_) => return false,
            ScramParse::Completed => return true
        }
    }

    /// Extracts data from Output(...). Will throw an error if
    /// current state is Completed.
    pub fn extract_output(self) -> ScramResult<String>
    {
        match self
        {
            ScramParse::Output(r) => return Ok(r),
            ScramParse::Completed => 
                scram_error!(ScramErrorCode::InternalError, 
                            "completed, nothing to extract"),
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
    pub fn none() -> Self
    {
        return Self::None;
    }

    /// Initialize ScramNonce with plain data.
    pub fn plain(p: &'sn [u8]) -> ScramNonce<'sn>
    {
        return Self::Plain(p);
    }

    /// Initialize ScramNonce with base64 encoded nonce. 
    pub fn base64(b: &'sn str) -> ScramNonce<'sn>
    {
        return Self::Base64(b);
    }

    /// Extract Nonce
    /// Will throw error if base64 will fail to encode the provided data to base64.
    /// Will throw error if argument length is 0.
    pub fn get_nonce(self) -> ScramResult<String>
    {
        match self
        {
            ScramNonce::None => return Ok(base64::encode(ScramCommon::sc_random(ScramCommon::SCRAM_RAW_NONCE_LEN)?)),
            ScramNonce::Plain(p) => 
            {
                if p.len() > ScramCommon::SCRAM_RAW_NONCE_LEN
                {
                    scram_error!(ScramErrorCode::InternalError,
                                "nonce length is > {}, actual: '{}'", 
                                ScramCommon::SCRAM_RAW_NONCE_LEN, p.len());
                }

                return Ok(base64::encode(p));
            },
            ScramNonce::Base64(b) => 
            {
                if b.len() == 0
                {
                    scram_error!(ScramErrorCode::InternalError,
                                "base64 nonce length is 0");
                }
                
                return Ok(b.to_string())
            }
        };
    }
}

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
pub struct ScramServer<'ss, S: ScramHashing, A: ScramAuthServer<S>>
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

impl<'ss, S: ScramHashing, A: ScramAuthServer<S>> ScramServer<'ss, S, A>
{
    /// Returns the supported types in format SCRAM SCRAM SCRAM
    pub fn advertise_types() -> String
    {
        return ScramCommon::adrvertise(" ");
    }

    /// Creates new instance of the ScramServer with lifetime 'ss
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
    pub fn new(scram_auth_serv: &'ss A,
                data_chanbind: Option<Vec<u8>>, 
                scram_nonce: ScramNonce, 
                st: &'ss ScramType) -> ScramResult<ScramServer<'ss, S, A>>
    {
        if st.scram_chan_bind == true && data_chanbind.is_none() == true
        {
            scram_error!(ScramErrorCode::ExternalError,
                        "scram: '{}' requires the data_chanbind to be set",
                        st);
        }

        let res = Self
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

    /// Decodes the input from base64 and performes parsing and result computation.  
    /// 
    /// # Arguments
    /// 
    /// * `input` - A response from client.
    /// 
    /// # Returns
    /// 
    /// * ScramResult<[ScramParse]> the response will be encoded to UTF-8
    pub fn parse_response_base64<T: AsRef<[u8]>>(&mut self, input: T) -> ScramResult<ScramParse>
    {
        let decoded = base64::decode(input)
                            .map_err(|e| scram_error_map!(ScramErrorCode::MalformedScramMsg, 
                                                        "base64 decode client response failed, '{}'", e))?;

        let dec_utf8 = 
            str::from_utf8(&decoded)
                .map_err(|e| scram_error_map!(ScramErrorCode::MalformedScramMsg, 
                                            "base64 decoded response contains invalid UTF-8 seq, '{}'", e))?;

        return self.parse_response(dec_utf8, true);
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
    pub fn parse_response(&mut self, resp: &str, to_base: bool) -> ScramResult<ScramParse>
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
                    match self.auth.get_password_for_user(user)
                    {
                        Some(r) => r,
                        None => 
                            scram_error!(ScramErrorCode::ExternalError,
                                        "authentification server failed for unknown reason"),
                    };

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

                if to_base == true
                {
                    return Ok(ScramParse::Output(base64::encode(output)));
                }
                else
                {
                    return Ok(ScramParse::Output(output));
                }
            },
            ScramData::SmsgInitial{..} => 
            {
                panic!("server can not handle state: {}", parsed_resp);
            },
            //final message from client (STEP 2)
            ScramData::CmsgFinalMessage{chanbinding, finalnonce, proof, client_nonce} =>
            {
                // verify channel bind
                self.cli_chanbind.server_final_verify_client_cb(
                        self.st, 
                        chanbinding,
                        self.data_chanbind.as_ref())?;

                let nonce = [client_nonce.as_str(), self.server_nonce.as_str()].concat();

                // verify nonce
                if finalnonce != nonce.as_str()
                {
                    scram_error!(ScramErrorCode::VerificationError,
                                "received invalid nonce rcvn: {} have: {}", finalnonce, client_nonce);
                }

                /*let cb_data = base64::encode(
                    [
                        self.cli_chanbind.convert2header(), 
                        self.cli_chanbind.convert2data()
                    ].concat());*/
    
                //base64 config
                
                let client_final_without_proof = ["c=", chanbinding, ",r=", &nonce].concat();
                let client_first_bare = ["n=", self.username.as_ref().unwrap(), ",r=", client_nonce].concat();
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
                
                
                let client_key = S::hmac(b"Client Key", &self.sp.get_salted_hashed_password())?;
                let server_key = S::hmac(b"Server Key", &self.sp.get_salted_hashed_password())?;
                let stored_key = S::hash(&client_key);
                let client_signature = S::hmac(authmsg.as_bytes(), &stored_key)?;
                let server_signature = S::hmac(authmsg.as_bytes(), &server_key)?;

                let calc_client_proof = ScramDataParser::xor_arrays(&client_key, &client_signature)?;

                // verify proof
                let recv_decoded_proof = 
                                base64::decode(proof)
                                        .map_err(|e| scram_error_map!(ScramErrorCode::MalformedScramMsg, 
                                                                     "base64 decode client proof failed, {}", e))?;
                if calc_client_proof != recv_decoded_proof
                {
                    scram_error!(ScramErrorCode::VerificationError,
                                "received invalid proof from client");
                }

                let output = 
                    [
                        "v=", &base64::encode(&server_signature),
                    ].concat();

                // update states
                self.state = ScramState::Completed;

                if to_base == true
                {
                    return Ok(ScramParse::Output(base64::encode(output)));
                }
                else
                {
                    return Ok(ScramParse::Output(output));
                }
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
pub struct ScramClient<'sc, S: ScramHashing, A: ScramAuthClient>
{
    /// A hasher picked
    hasher: PhantomData<S>,
    /// A authentification callback
    auth: &'sc A,
    /// A client generated/picked nonce
    client_nonce: String,
    /// A current state step
    state: ScramState,
    /// A type of the channel bind [ClientChannelBindingType]
    chanbind: ClientChannelBindingType,
}

impl<'sc, S: ScramHashing, A: ScramAuthClient> ScramClient<'sc, S, A>
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
    /// let scram_res = ScramClient::<ScramSha256, AuthClient>::new(&ac, nonce, cbt);
    /// ```
    pub fn new(scram_auth_cli: &'sc A, 
                scram_nonce: ScramNonce, 
                chan_bind_type: ClientChannelBindingType) -> ScramResult<ScramClient<'sc, S, A>>
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
    pub fn is_completed(&self) -> bool
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
    pub fn init_client(&mut self, to_base64: bool) -> String
    {            
        let compiled = [self.chanbind.convert2header(),
                        b"n=", self.auth.get_username().as_bytes(),
                        b",r=", &self.client_nonce.as_bytes()].concat();
        
        self.state = ScramState::WaitForServInitMsg;     
        
        if to_base64 == true
        {
            return base64::encode(compiled);
        }
        else
        {
            return unsafe {String::from_utf8_unchecked(compiled)};
        }
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
    pub fn parse_response_base64<T: AsRef<[u8]>>(&mut self, input: T) -> ScramResult<ScramParse>
    {
        let decoded = base64::decode(input)
                            .map_err(|e| scram_error_map!(ScramErrorCode::MalformedScramMsg, 
                                                        "base64 decode server response failed, '{}'", e))?;

        let dec_utf8 = 
            str::from_utf8(&decoded)
                .map_err(|e| scram_error_map!(ScramErrorCode::MalformedScramMsg, 
                                            "base64 decoded response contains invalid UTF-8 seq, '{}'", e))?;

        return self.parse_response(dec_utf8, true);
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
    pub fn parse_response(&mut self, resp: &str, to_base64: bool) -> ScramResult<ScramParse>
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
                if itrcnt == 0 || itrcnt > 100000
                {
                    scram_error!(ScramErrorCode::InternalError, 
                                "iterations count is not appropriate: i='{}'", itrcnt);
                }

                //todo channel bind things SASL 
                let cb_data = base64::encode(
                                [
                                    self.chanbind.convert2header(), 
                                    self.chanbind.convert2data()
                                ].concat());

                let client_final_message_bare = ["c=", &cb_data, ",r=", nonce].concat();

                let authmsg = 
                            [
                                b"n=", self.auth.get_username().as_bytes(),
                                b",r=", self.client_nonce.as_bytes(), 
                                b",", resp.as_bytes(),
                                b",", client_final_message_bare.as_bytes()
                            ].concat();

                let salted_password = S::derive(self.auth.get_password().as_bytes(), &salt, itrcnt)?;
                let client_key = S::hmac(b"Client Key", &salted_password)?;
                let server_key = S::hmac(b"Server Key", &salted_password)?;

                

                let stored_key = S::hash(&client_key);
                let client_signature = S::hmac(&authmsg, &stored_key)?;
                let server_signature = S::hmac(&authmsg, &server_key)?;
                
                let client_response = [
                                        &client_final_message_bare,
                                        ",p=",
                                        &base64::encode(ScramDataParser::xor_arrays(&client_key, &client_signature)?)
                                    ].concat();
                

                self.state = ScramState::WaitForServFinalMsg{server_signature: server_signature};
                
                if to_base64 == true
                {
                    return Ok(ScramParse::Output(base64::encode(client_response)));
                }
                else
                {
                    return Ok(ScramParse::Output(client_response));
                }
                
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

                    return Ok(ScramParse::Completed);
                }
                else
                {
                    scram_error!(ScramErrorCode::VerificationError,
                                "state: '{}', server signature mismatch, \
                                server sig: '{:x?}', local: {:x?}",
                                self.state, server_verifier, verifier);
                }

            }
        }
    }
}

/// Parsed data storage with lifetime 'par.
enum ScramData<'par>
{
    /// first message from client in the context of a SCRAM
    CmsgInitial
    {
        /// n, or y, or p=<val>
        chan_bind: ServerChannelBindType,
        //authid and other is not supported
        /// "n=" saslname
        user: &'par str,
        /// r=" c-nonce [s-nonce]
        nonce: &'par str
    },

    /// first server-side message sent to the client in a SCRAM
    SmsgInitial
    {
        /// "r=" c-nonce [s-nonce]
        nonce: &'par str,
        /// "s=" base64
        salt: Vec<u8>,
        /// "i=" posit-number
        itrcnt: u32,
    },

    /// client final message
    CmsgFinalMessage
    {
        /// "c=" base64 [biws == n] [eSws == y]
        chanbinding: &'par str,
        /// "r=" base64 (final nonce)
        finalnonce: &'par str,
        /// "p=" base64 (proof)
        proof: &'par str,
        ///stored client_nonce
        client_nonce: &'par String,
    },

    /// server final message 
    SmsgFinalMessage
    {
        /// "v=" base64 base-64 encoded ServerSignature.
        verifier: Vec<u8>,
        /// stored server verifier
        server_verifier: &'par Vec<u8>,
    },
}

impl<'par> fmt::Display for ScramData<'par>
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        match *self 
        {
            Self::CmsgFinalMessage{..} => write!(f, "CmsgFinalMessage"),
            Self::CmsgInitial{..} => write!(f, "CmsgInitial"),
            Self::SmsgFinalMessage{..} => write!(f, "SmsgFinalMessage"),
            Self::SmsgInitial{..} => write!(f, "SmsgInitial"),
        }
    }
}

/// A data parser instance with lifetime 'par.
struct ScramDataParser<'par>
{
    srcmsg: &'par str,
    chars: Peekable<Chars<'par>>,
    pos: usize,
    curchar: Option<char>,
}

impl<'par> ScramDataParser<'par>
{
    /// Initializes a parser from raw str. It requires current state of the Scram machine to
    /// determine the response sub-parser.
    pub fn from_raw(resp: &'par str, scramstate: &'par ScramState) -> ScramResult<ScramData<'par>>
    {
        let mut c = resp.chars().peekable();
        let cur: Option<char>;

        // skip all \d\a
        match c.next()
        {
            Some(r) =>
            {
                cur = Some(r);
            },
            None => scram_error!(ScramErrorCode::MalformedScramMsg, 
                                "state: '{}', unexpected EOF while parsing", scramstate),
        }            
        

        let mut inst = ScramDataParser
        {
            srcmsg: resp,
            chars: c,
            pos: 0,
            curchar: cur,
        };

        let res = match scramstate
        {
            ScramState::WaitForClientInitalMsg =>
            {
                inst.parsing_client_init_msg()?
            },
            ScramState::WaitForServInitMsg =>
            {
                inst.parsing_server_init_reply()?
            },
            ScramState::WaitForClientFinalMsg{client_nonce} =>
            {
                inst.parsing_clinet_final_msg(client_nonce)?
            },
            ScramState::WaitForServFinalMsg{server_signature} =>
            {
                inst.parsing_server_final_reply(server_signature)?
            },
            _ => scram_error!(ScramErrorCode::InternalError,
                            "state {} not implemented \
                            or does not require handling", scramstate),
        };
         
        return Ok(res);
    }

    #[inline] 
    fn move_next(&mut self) -> ScramResult<()>
    {
        self.pos += 1;

        self.curchar = self.chars.next();

        if let Some(ref x) = self.curchar
        {
            if x.is_ascii_graphic() == false
            {
                scram_error!(ScramErrorCode::MalformedScramMsg,
                            "malformed scram message, \
                            expected ASCII char \
                            but found char: {} near position: {}", 
                            ScramDataParser::sanitize_char(*x),
                            self.pos);
            }
        }

        return Ok(());
    }

    #[inline]
    fn get_cur_char(&self) -> Option<char>
    {
        return self.curchar;
    }

    #[inline]
    fn get_cur_char_e(&self) -> ScramResult<char>
    {
        match self.curchar
        {
            Some(r) => return Ok(r),
            None => scram_error!(ScramErrorCode::MalformedScramMsg,
                                "Unexpected eof at {}", self.pos),
        }
    }

    #[allow(dead_code)]
    #[inline]
    fn foresee_char(&mut self) -> Option<char>
    {
        return match self.chars.peek()
        {
            Some(c) => Some(*c),
            None => None
        };
    }

    #[inline]
    fn foresee_char_e(&mut self) -> ScramResult<char>
    {
        return match self.chars.peek()
        {
            Some(c) => Ok(*c),
            None => scram_error!(ScramErrorCode::MalformedScramMsg,
                                "Unexpected eof at {}", self.pos),
        };
    }

    fn read_find_parameter(&mut self, par: char) -> ScramResult<&'par str>
    {
        loop
        {
            match self.get_cur_char()
            {
                None => scram_error!(ScramErrorCode::MalformedScramMsg,
                                    "parameter '{}' was not found", par),
                Some(c) =>
                {
                    let pardata = self.read_parameter(c)?;
                    if c == par
                    {
                        return Ok(pardata);
                    }
                }
            }
        }
    }

    fn read_parameter(&mut self, par: char) -> ScramResult<&'par str>
    {
        if self.get_cur_char_e()? != par
        {
            scram_error!(ScramErrorCode::MalformedScramMsg,
                        "expected paramenter '{}' \
                        but found char: '{}' near position: '{}'", 
                        par,
                        ScramDataParser::sanitize_char(self.get_cur_char_e()?),
                        self.pos);
        }

        self.move_next()?;

        if self.get_cur_char_e()? != '='
        {
            scram_error!(ScramErrorCode::MalformedScramMsg,
                        "expected '=' \
                        but found char: '{}' near position: '{}'", 
                        ScramDataParser::sanitize_char(self.get_cur_char_e()?),
                        self.pos);
        }
        
        self.move_next()?;

        let initpos = self.pos;
        loop
        {
            match self.get_cur_char()
            {
                None => break,
                Some(c) =>
                {
                    if c == ','
                    {
                        break;
                    }
                    else
                    {
                        self.move_next()?;
                    }
                }
            }
        }

        let ret = &self.srcmsg[initpos..self.pos];
        
        self.move_next()?;
        return Ok(ret);
    }

    /// Parsing the First Reply from Server SMSG_...
    /// 
    /// The syntax for the server-first-message is: (RFC 5802)
    /// server-first-message = [reserved-mext ","] nonce "," salt ","
    ///                       iteration-count ["," extensions]
    /// nonce                = "r=" c-nonce [s-nonce]
    ///                      ;; Second part provided by server.
    /// c-nonce              = printable
    /// s-nonce              = printable
    /// salt                 = "s=" base64
    /// iteration-count      = "i=" posit-number
    ///                      ;; A positive number.
    /// r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096
    fn parsing_server_init_reply(&mut self) -> ScramResult<ScramData<'par>>
    {

        let nonce = self.read_parameter('r')?;

        // check if nonce is printable
        ScramDataParser::q_scram_printable(&nonce)?;

        let ret = ScramData::SmsgInitial
            {
                nonce: nonce,
                salt: base64::decode(self.read_parameter('s')?)
                                .map_err(|e| scram_error_map!(ScramErrorCode::MalformedScramMsg, 
                                                            "parameter v= conversion err, {}", e))?,
                itrcnt: u32::from_str_radix(self.read_parameter('i')?, 10)
                            .map_err(|e| scram_error_map!(ScramErrorCode::MalformedScramMsg, 
                                                        "parameter i= conversion err, {}", e))?,
            };

        return Ok(ret);
    }

    /// v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=
    fn parsing_server_final_reply(&mut self, server_verifier: &'par Vec<u8>) -> ScramResult<ScramData<'par>>
    {
        let ret = ScramData::SmsgFinalMessage
            {
                verifier: base64::decode(self.read_parameter('v')?)
                                    .map_err(|e| scram_error_map!(ScramErrorCode::MalformedScramMsg, 
                                                                    "parameter v= conversion err, {}", e))?,
                server_verifier: server_verifier,
            };

        return Ok(ret);
    }

    fn parsing_client_init_msg(&mut self) -> ScramResult<ScramData<'par>>
    {
        // n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
        
        let chanbinding = match self.get_cur_char_e()?
            {
                'n' => 
                {
                    // the client does not support channel binding
                    self.move_next()?;

                    if self.get_cur_char_e()? != ','
                    {
                        scram_error!(ScramErrorCode::MalformedScramMsg,
                                    "expected ',' \
                                    but found char: {} near position: {}", 
                                    ScramDataParser::sanitize_char(self.foresee_char_e()?),
                                    self.pos);
                    }

                    // current n,

                    ServerChannelBindType::n()
                },
                'y' =>
                {
                    // the client sipports channel binding but thinks server does not
                    self.move_next()?;

                    if self.get_cur_char_e()? != ','
                    {
                        scram_error!(ScramErrorCode::MalformedScramMsg,
                                    "expected ',' \
                                    but found char: '{}' near position: '{}'", 
                                    ScramDataParser::sanitize_char(self.get_cur_char_e()?),
                                    self.pos);
                    }

                    ServerChannelBindType::y()
                },
                'p' =>
                {
                    // the client requires channel binding i.e p=tls-server-end-point
                    // read =data

                    let par = self.read_parameter('p')?;
                    //p=..., curchar: ,

                    ServerChannelBindType::from_str(par)?
                },
                _ => scram_error!(ScramErrorCode::MalformedScramMsg,
                                "expected 'n,|y,|p=' \
                                but found char: '{}' near position: '{}'", 
                                ScramDataParser::sanitize_char(self.get_cur_char_e()?),
                                self.pos),
            };
        
        
        self.move_next()?;
        
        // authzid  is not supported
        match self.get_cur_char_e()?
        {
            'a' => scram_error!(ScramErrorCode::FeatureNotSupported, 
                                "client uses authorization identity (a=), but it is not supported!"),
            ',' => self.move_next()?,
            _ => scram_error!(ScramErrorCode::MalformedScramMsg, 
                            "expected '=' \
                            but found char: '{}' near position: '{}'", 
                            ScramDataParser::sanitize_char(self.get_cur_char_e()?),
                            self.pos),
        }
        
        if self.get_cur_char_e()? == 'm'
        {
            scram_error!(ScramErrorCode::FeatureNotSupported,
                        "client requires an unsupported SCRAM extension! (m=)");
        }

        let username = self.read_parameter('n')?;
        let nonce = self.read_parameter('r')?;

        // check if nonce is printable
        ScramDataParser::q_scram_printable(&nonce)?;

        // any left data is ignored
        
        let ret = ScramData::CmsgInitial
            {
                chan_bind: chanbinding,
                user: username,
                nonce: nonce,
            };

        return Ok(ret);
    }

    /// c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=
    fn parsing_clinet_final_msg(&mut self, client_nonce: &'par String) -> ScramResult<ScramData<'par>>
    {
        let chanbinding = self.read_parameter('c')?;
        let finalnonce = self.read_parameter('r')?;
        let proof = self.read_find_parameter('p')?;

        ScramDataParser::q_scram_printable(chanbinding)?;

        let ret = ScramData::CmsgFinalMessage
            {
                chanbinding: chanbinding,
                finalnonce: finalnonce,
                proof: proof,
                client_nonce: client_nonce,
            };

        return Ok(ret);
    }

    /// Internal function used to XOR 2 arrays
    fn xor_arrays(a: &[u8], b: &[u8]) -> ScramResult<Vec<u8>>
    {
        if a.len() != b.len()
        {
            scram_error!(ScramErrorCode::InternalError,
                        "xor arrays size mismatch: a: '{}', b: '{}'", a.len(), b.len());
        }

        let mut ret = Vec::with_capacity(a.len());
        for (a, b) in a.into_iter().zip(b) 
        {
            ret.push(a ^ b);
        }
        
        return Ok(ret);
    }

    fn q_scram_printable(a: &'par str) -> ScramResult<()>
    {
        for p in a.chars()
        {
            // p < 0x21 || p > 0x7E
            if p.is_ascii_graphic() == false || p.is_ascii() == false || p == ','
            {
                scram_error!(ScramErrorCode::MalformedScramMsg,
                            "non-printable characters in SCRAM nonce");
            }
        }

        return Ok(());
    }

    fn sanitize_char(c: char) -> String
    {
        if c.is_ascii_graphic() == true
        {
            return c.to_string();
        }
        else
        {
            return format!("{:#x}", c as u64);
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
        fn get_password_for_user(&self, _username: &str) -> Option<ScramPassword>
        {
            let password = "pencil";
            let salt = b"[m\x99h\x9d\x125\x8e\xec\xa0K\x14\x126\xfa\x81".to_vec();

            Some(ScramPassword::found_secret_password(
                    ScramSha256::derive(password.as_bytes(), &salt, 4096).unwrap(),
                    base64::encode(salt), 
                    4096))

                    
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
    let scram_res = ScramServer::<ScramSha256, AuthServer>::new(&serv, None, nonce, scramtype);
    assert_eq!(scram_res.is_ok(), true);

    let mut scram = scram_res.unwrap();

    let start = Instant::now();
    let resp_res = scram.parse_response(client_init, false);

    assert_eq!(resp_res.is_ok(), true);

    let resp = resp_res.unwrap().extract_output().unwrap();
    assert_eq!( resp.as_str(), server_init ); 

    let resp_res = scram.parse_response(client_final, false);
    if resp_res.is_err() == true
    {
        println!("{}", resp_res.err().unwrap());
        assert_eq!(false, true);
        return;
    }
    
    let el = start.elapsed();
    println!("took: {:?}", el);

    let resp = resp_res.unwrap().extract_output().unwrap();
    assert_eq!( resp.as_str(), server_final ); 
}

#[test]
fn scram_sha256_works() 
{ 
    use std::time::Instant;
    use super::scram_hashing::ScramSha256;
    use super::scram_auth::ScramAuthClient;

    struct AuthClient
    {
        username: String,
        password: String,
    }

    impl ScramAuthClient for AuthClient
    {
        fn get_username(&self) -> &String
        {
            return &self.username;
        }

        fn get_password(&self) -> &String
        {
            return &self.password;
        }
    }

    impl AuthClient
    {
        pub fn new(u: &'static str, p: &'static str) -> Self
        {
            return AuthClient{username: u.to_string(), password: p.to_string()};
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

    let scram_res = ScramClient::<ScramSha256, AuthClient>::new(&ac, nonce, cbt);
    assert_eq!(scram_res.is_ok(), true);

    let mut scram = scram_res.unwrap();
    
    let init = scram.init_client(false);
    assert_eq!( init.as_str(), client_init ); 

    let resp_res = scram.parse_response(server_init, false);
    assert_eq!(resp_res.is_ok(), true);

    let resp = resp_res.unwrap().extract_output().unwrap();
    assert_eq!( resp.as_str(), client_final ); 

    let res = scram.parse_response(server_final, false);
    assert_eq!(res.is_ok(), true);

    let el = start.elapsed();
    println!("took: {:?}", el);

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
