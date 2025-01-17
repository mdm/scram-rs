/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::fmt;
use std::str;
use std::str::Chars;
use std::iter::Peekable;

use base64::Engine;
use base64::engine::general_purpose;

use crate::ScramCommon;
use crate::ScramServerError;

use super::scram_error::{ScramResult, ScramErrorCode};
use super::{scram_error, scram_error_map, scram_ierror};
use super::scram_cb::ChannelBindType;
use super::scram_state::ScramState;

/// Parsed data storage with lifetime 'par.
pub(crate) enum ScramData<'par>
{
    /// first message from client in the context of a SCRAM
    CmsgInitial
    {
        /// n, or y, or p=<val>
        chan_bind: ChannelBindType,
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
        /// stored client_nonce
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
pub(crate) struct ScramDataParser<'par>
{
    pos: usize,
    srcmsg: &'par str,
    chars: Peekable<Chars<'par>>,
    curchar: Option<char>,
}

impl<'par> ScramDataParser<'par>
{
    /// Initializes a parser from raw str. It requires current state of the Scram machine to
    /// determine the response sub-parser.
    pub(crate) 
    fn from_raw(resp: &'par str, scramstate: &'par ScramState) -> ScramResult<ScramData<'par>>
    {
        let mut c = resp.chars().peekable();

        // skip all \d\a

        let cur: Option<char> = 
            match c.next()
            {
                Some(r) => Some(r),
                None => 
                    scram_error!(ScramErrorCode::MalformedScramMsg, ScramServerError::OtherError,
                        "state: '{}', unexpected EOF while parsing", scramstate),
            };       
            

        let mut inst = 
            ScramDataParser
            {
                srcmsg: resp,
                chars: c,
                pos: 0,
                curchar: cur,
            };

        let res = 
            match scramstate
            {
                ScramState::WaitForClientInitalMsg =>
                    inst.parsing_client_init_msg()?,

                ScramState::WaitForServInitMsg =>
                    inst.parsing_server_init_reply()?,

                ScramState::WaitForClientFinalMsg{client_nonce} =>
                    inst.parsing_clinet_final_msg(client_nonce)?,

                ScramState::WaitForServFinalMsg{server_signature} =>
                    inst.parsing_server_final_reply(server_signature)?,

                _ => 
                    scram_error!(
                        ScramErrorCode::InternalError,
                        ScramServerError::OtherError,
                        "state {} not implemented or does not require handling", scramstate
                    ),
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
                scram_error!(
                    ScramErrorCode::MalformedScramMsg,
                    ScramServerError::OtherError,
                    "malformed scram message, expected ASCII char but found char: {} near position: {}", 
                    ScramCommon::sanitize_char(*x),
                    self.pos
                );
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
            Some(r) => 
                return Ok(r),
            None => 
                scram_error!(ScramErrorCode::MalformedScramMsg, ScramServerError::OtherError,
                    "Unexpected eof at {}", self.pos),
        }
    }

    #[allow(dead_code)]
    #[inline]
    fn foresee_char(&mut self) -> Option<char>
    {
        return 
            match self.chars.peek()
            {
                Some(c) => Some(*c),
                None => None
            };
    }

    #[inline]
    fn foresee_char_e(&mut self) -> ScramResult<char>
    {
        return 
            match self.chars.peek()
            {
                Some(c) => Ok(*c),
                None => 
                    scram_error!(ScramErrorCode::MalformedScramMsg, ScramServerError::OtherError,
                        "Unexpected eof at {}", self.pos),
            };
    }

    fn read_find_parameter(&mut self, par: char) -> ScramResult<&'par str>
    {
        loop
        {
            match self.get_cur_char()
            {
                None => 
                    scram_error!(ScramErrorCode::MalformedScramMsg, ScramServerError::OtherError,
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
            scram_error!(
                ScramErrorCode::MalformedScramMsg,
                ScramServerError::OtherError,
                "expected paramenter '{}' but found char: '{}' near position: '{}'", 
                par,
                ScramCommon::sanitize_char(self.get_cur_char_e()?),
                self.pos
            );
        }

        self.move_next()?;

        if self.get_cur_char_e()? != '='
        {
            scram_error!(
                ScramErrorCode::MalformedScramMsg,
                ScramServerError::OtherError,
                "expected '=' but found char: '{}' near position: '{}'", 
                ScramCommon::sanitize_char(self.get_cur_char_e()?),
                self.pos
            );
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
        // it is not clear if this is part of the RFC but this lib demonstrates such tricks,
        // in case of internal error.
        if self.get_cur_char_e()? == 'e'
        {
            let err_type = self.read_parameter('e')?;
            let cerr_type = ScramServerError::from(err_type);

            scram_error!(ScramErrorCode::ClientSide, cerr_type, "{}", cerr_type);
        }

        let nonce = self.read_parameter('r')?;

        // check if nonce is printable
        ScramDataParser::q_scram_printable(&nonce)?;

        let salt = 
            general_purpose::STANDARD.decode(self.read_parameter('s')?)
                .map_err(|e| 
                    scram_error_map!(
                        ScramErrorCode::MalformedScramMsg, 
                        ScramServerError::InvalidEncoding,
                        "parameter s= conversion err, {}", e
                    )
                )?;

        let itrcnt = 
            i32::from_str_radix(self.read_parameter('i')?, 10)
                .map_err(|e| 
                    scram_error_map!(
                        ScramErrorCode::MalformedScramMsg, 
                        ScramServerError::OtherError,
                        "parameter i= conversion err, {}", e
                    )
                )?;

        if itrcnt < 0
        {
            scram_error!(ScramErrorCode::MalformedScramMsg, ScramServerError::OtherError, 
                "parameter i= '{}' is negative!", itrcnt);
        }

        let ret = 
            ScramData::SmsgInitial
            {
                nonce: nonce,
                salt: salt,
                itrcnt: itrcnt as u32
            };

        return Ok(ret);
    }

    /// v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4= / e=invalid-proof
    fn parsing_server_final_reply(&mut self, server_verifier: &'par Vec<u8>) -> ScramResult<ScramData<'par>>
    {
        let par = self.get_cur_char_e()?;
        match par
        {
            'v' => 
            {
                let ret = 
                    ScramData::SmsgFinalMessage
                    {
                        verifier: 
                            general_purpose::STANDARD.decode(self.read_parameter('v')?)
                                .map_err(|e| 
                                    scram_error_map!(ScramErrorCode::MalformedScramMsg, ScramServerError::InvalidEncoding,
                                        "parameter v= conversion err, {}", e)
                                )?,
                        server_verifier: server_verifier,
                    };

                return Ok(ret);
            },
            'e' =>
            {
                let err_type = self.read_parameter('e')?;
                let cerr_type = ScramServerError::from(err_type);

                scram_error!(ScramErrorCode::ClientSide, cerr_type, "{}", cerr_type);
            },
            _ =>
            {
                scram_ierror!(ScramErrorCode::MalformedScramMsg, 
                    "final reply contains unknown parameter '{}'", ScramCommon::sanitize_char(par));
            }
        }
        
    }

    fn parsing_client_init_msg(&mut self) -> ScramResult<ScramData<'par>>
    {
        // n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
        
        let chanbinding = 
            match self.get_cur_char_e()?
            {
                'n' => 
                {
                    // the client does not support channel binding
                    self.move_next()?;

                    if self.get_cur_char_e()? != ','
                    {
                        scram_error!(
                            ScramErrorCode::MalformedScramMsg,
                            ScramServerError::OtherError,
                            "expected ',' but found char: {} near position: {}", 
                            ScramCommon::sanitize_char(self.foresee_char_e()?),
                            self.pos
                        );
                    }

                    // current n,

                    ChannelBindType::n()
                },
                'y' =>
                {
                    // the client sipports channel binding but thinks server does not
                    self.move_next()?;

                    if self.get_cur_char_e()? != ','
                    {
                        scram_error!(
                            ScramErrorCode::MalformedScramMsg,
                            ScramServerError::OtherError,
                            "expected ',' but found char: '{}' near position: '{}'", 
                            ScramCommon::sanitize_char(self.get_cur_char_e()?),
                            self.pos
                        );
                    }

                    ChannelBindType::y()
                },
                'p' =>
                {
                    // the client requires channel binding i.e p=tls-server-end-point
                    // read =data

                    let par = self.read_parameter('p')?;
                    //p=..., curchar: ,

                    ChannelBindType::from_str(par)?
                },
                _ => 
                {
                    scram_error!(
                        ScramErrorCode::MalformedScramMsg,
                        ScramServerError::OtherError,
                        "expected 'n,|y,|p=' but found char: '{}' near position: '{}'", 
                        ScramCommon::sanitize_char(self.get_cur_char_e()?),
                        self.pos
                    );
                },
            };
        
        
        self.move_next()?;
        
        // authzid  is not supported
        match self.get_cur_char_e()?
        {
            'a' => 
                scram_error!(
                    ScramErrorCode::FeatureNotSupported, 
                    ScramServerError::OtherError,
                    "client uses authorization identity (a=), but it is not supported!"
                ),
            ',' => self.move_next()?,
            _ => 
                scram_error!(
                    ScramErrorCode::MalformedScramMsg, 
                    ScramServerError::OtherError,
                    "expected '=' but found char: '{}' near position: '{}'", 
                    ScramCommon::sanitize_char(self.get_cur_char_e()?),
                    self.pos
                ),
        }
        
        if self.get_cur_char_e()? == 'm'
        {
            scram_error!(
                ScramErrorCode::FeatureNotSupported, 
                ScramServerError::ExtensionsNotSupported,
                "client requires an unsupported SCRAM extension! (m=)"
            );
        }

        // if previosly the provided raw data for parsing was converted to
        // str with utf8 validation, it should be UTF8 safe
        let username = self.read_parameter('n')?;
        let nonce = self.read_parameter('r')?;

        // check if nonce is printable
        ScramDataParser::q_scram_printable(nonce)?;
        ScramDataParser::u_scram_printable(username)?;

        // any left data is ignored
        
        let ret = 
            ScramData::CmsgInitial
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

        let ret = 
            ScramData::CmsgFinalMessage
            {
                chanbinding: chanbinding,
                finalnonce: finalnonce,
                proof: proof,
                client_nonce: client_nonce,
            };

        return Ok(ret);
    }

    /// Internal function used to XOR 2 arrays
    pub(crate) 
    fn xor_arrays(a: &[u8], b: &[u8]) -> ScramResult<Vec<u8>>
    {
        if a.len() != b.len()
        {
            scram_error!(
                ScramErrorCode::InternalError,
                ScramServerError::OtherError,
                "xor arrays size mismatch: a: '{}', b: '{}'", a.len(), b.len()
            );
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
                scram_error!(ScramErrorCode::MalformedScramMsg, ScramServerError::OtherError,
                    "non-printable characters in SCRAM nonce");
            }
        }

        return Ok(());
    }

    fn u_scram_printable(u: &'par str) -> ScramResult<()>
    {
        for p in u.chars()
        {
            // any character that can be printed except control chars
            if p.is_control() == true || p.is_ascii_whitespace() == true || p.is_ascii_control() == true
            {
                scram_error!(ScramErrorCode::MalformedScramMsg, ScramServerError::InvalidUsernameEncoding,
                    "non-printable characters in SCRAM username: {}", ScramCommon::sanitize_str_unicode(u));
            }
        }

        return Ok(());
    }
}
