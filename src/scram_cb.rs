/*-
* Scram-rs
* Copyright (C) 2021  Aleksandr Morozov
* 
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU Affero General Public License for more details.
* 
* You should have received a copy of the GNU Affero General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

use std::fmt;

use super::scram_error::{ScramResult, ScramRuntimeError, ScramErrorCode};
use super::{scram_error, scram_error_map};

pub enum ChannelBinding 
{
    /// No channel binding data.
    None,
    /// Advertise that the client does not think the server supports channel binding.
    Unsupported,
    /// p=tls-unique channel binding data.
    TlsUnique,
    /// p=tls-server-end-point
    TlsServerEndpoint
}

impl fmt::Display for ChannelBinding
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        match *self 
        {
            Self::None => write!(f, "None"),
            Self::Unsupported => write!(f, "Unsupported"),
            Self::TlsUnique => write!(f, "TlsUnique"),
            Self::TlsServerEndpoint => write!(f, "TlsServerEndpoint"),
        }
    }
}

impl ChannelBinding
{
    pub fn initial_verify_cb(&self, is_plus: bool) -> ScramResult<()>
    {
        if is_plus == true
        {
            // server with channel binding support
            match *self
            {
                Self::TlsUnique => 
                    scram_error!(ScramErrorCode::MalformedScramMsg,
                                "unsupported SCRAM channel-binding type {}!", self),

                Self::TlsServerEndpoint => return Ok(()),

                Self::None => 
                    scram_error!(ScramErrorCode::MalformedScramMsg,
                                "malformed message, client selected *-PLUS but message does not include cb data!"),

                Self::Unsupported => 
                    scram_error!(ScramErrorCode::MalformedScramMsg,
                                "malformed message, client picked -PLUS, but did not provide cb data"),
            }
        }
        else
        {
            // no support
            match *self
            {
                Self::TlsUnique | Self::TlsServerEndpoint => 
                    scram_error!(ScramErrorCode::MalformedScramMsg,
                                "client provided channel binding data while server does not support it!"),
                Self::None => return Ok(()),
                Self::Unsupported => return Ok(()),
            }
        }
    }

    pub fn final_verify_cb(&self, is_bind: bool, cb_attr: &str) -> ScramResult<()>
    {
        // verify input
        //If we are not using channel binding, the binding data is expected
        // to always be "biws", which is "n,," base64-encoded, or "eSws",
        // which is "y,,".  We also have to check whether the flag is the same
        // one that the client originally sent. auth-scram_8c_source.c:1310

        match *self
        {
            Self::TlsUnique | Self::TlsServerEndpoint =>
            {
                if is_bind == false
                {
                    panic!("assertion trap: cb_type: {}, is_bind: {}, so when is bind==true then cb_type must be \
                            either TlsUnique or TlsServerEndpoint", self, is_bind);
                }
                //try to implement prototype

                //Fetch hash data of server's SSL certificate
                panic!("implement in final_verify_cb");
                //cbind_data = be_tls_get_certificate_hash(state->port, &cbind_data_len); //todo
                let cbind_data = "mockvar";
                let header = 
                    [
                        "p=tls-server-end-point,,",
                        cbind_data
                    ].concat();
                
                let bheader = base64::encode(header);

                if bheader.as_str() == cb_attr
                {
                    return Ok(());
                }
                else
                {
                    scram_error!(ScramErrorCode::VerificationError,
                                "SCRAM channel binding check failed");
                }
            },
            Self::Unsupported => 
            {
                if cb_attr == "eSws"
                {
                    return Ok(());
                }
                else
                {
                    scram_error!(ScramErrorCode::ProtocolViolation,
                                "unexpected SCRAM channel-binding attribute in client-final-message: {}", cb_attr);
                }
            },
            Self::None =>
            {
                if cb_attr == "biws"
                {
                    return Ok(());
                }
                else
                {
                    scram_error!(ScramErrorCode::ProtocolViolation,
                                "unexpected SCRAM channel-binding attribute in client-final-message: {}", cb_attr);
                }
            }
        }
    }

    pub fn from_str<C: AsRef<str>>(cb: C) -> ScramResult<Self>
    {
        match cb.as_ref()
        {
            "none" => return Ok(Self::None),
            "unsupported" => return Ok(Self::Unsupported),
            "tlsunique" => return Ok(Self::TlsUnique),
            "tlsserverendpoint" => return Ok(Self::TlsServerEndpoint),
            _ => scram_error!(ScramErrorCode::ProtocolViolation,
                            "Unknown channel bind type: '{}'", cb.as_ref()),
        }
    }

    pub fn convert2header(&self) -> &str
    {
        match self
        {
            Self::None => return "n,,",
            Self::Unsupported => return "y,,",
            Self::TlsUnique => panic!("not supported yet"), //"p=tls-unique,,"
            Self::TlsServerEndpoint => panic!("not supported yet") //"p=tls-server-end-point,,"
        }
    }

    pub fn convert2data(&self) -> &str
    {
        match self
        {
            Self::None => return "",
            Self::Unsupported => return "",
            Self::TlsUnique => panic!("not supported yet"),
            Self::TlsServerEndpoint => panic!("not supported yet"),//(data)
        }
    }
}
