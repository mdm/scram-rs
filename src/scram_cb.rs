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
use std::io;
use std::fmt;

//use native_tls::TlsStream;

use super::scram_common::ScramType;
use super::scram_error::{ScramResult, ScramRuntimeError, ScramErrorCode};
use super::{scram_error, scram_error_map};

/*pub enum ChannelBinding<'ss, T: io::Read + io::Write>
{
    None,
    TlsStream{tlsstream: &'ss TlsStream<T>},
}

impl<'ss, T: io::Read + io::Write> ChannelBinding<'ss, T>
{
    pub fn none() -> Self
    {
        return Self::None;
    }

    pub fn tlsstream(tlsstream: &'ss TlsStream<T>) -> Self
    {
        return Self::TlsStream{tlsstream: tlsstream};
    }
}*/

pub enum ChannelBindingData
{
    None,
    TlsEndPoint{cb_data: Vec<u8>},
    TlsUnique,
}

impl fmt::Display for ChannelBindingData
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        match *self 
        {
            Self::None => write!(f, "None"),
            Self::TlsEndPoint{..} => write!(f, "TlsEndPoint"),
            Self::TlsUnique => write!(f, "TlsUnique"),
        }
    }
}

impl ChannelBindingData
{
    pub fn none() -> Self
    {
        return Self::None;
    }

    pub fn tls_endpoint(opt_cb_data: Option<Vec<u8>>) -> ScramResult<Self>
    {
        let cb_data = match opt_cb_data
            {
                Some(r) => r,
                None => scram_error!(ScramErrorCode::InternalError,
                                    "channel bind data for Tls Endpoint is \
                                    empty!")
            };
            
        return Ok(Self::TlsEndPoint{cb_data: cb_data});
    }

    pub fn tls_unique() -> Self
    {
        panic!("Tls uniq is not supported!");
    }

    pub fn get_endpoint_hash(&self) -> &[u8]
    {
        match *self
        {
            Self::TlsEndPoint{ref cb_data} => return cb_data,
            _ => panic!("misuse get_endpoint_hash(), used on type: {}", self),
        }
    }
}

pub enum ChannelBindingType
{
    /// No channel binding data.
    None,
    /// Advertise that the client does not think the server supports channel binding.
    Unsupported,
    /// p=tls-unique channel binding data.
    TlsUnique,
    /// p=tls-server-end-point
    TlsServerEndpoint,
}

impl fmt::Display for ChannelBindingType
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

impl ChannelBindingType
{
    pub fn n() -> Self
    {
        return Self::None;
    }

    pub fn y() -> Self
    {
        return Self::Unsupported;
    }

    pub fn tls_server_endpoint() -> Self
    {
        return Self::TlsServerEndpoint;
    }

    /// Verifies the client initial request about the Channel Bind
    /// If client picks SCRAM-? without -PLUS extension, then it should not
    /// require any channel binding i.e n -(None) or y-(Unsupported)
    pub fn server_initial_verify_client_cb(&self, st: &ScramType) -> ScramResult<()>
    {
        if st.scram_chan_bind == true
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
                //if client pickes -PLUS and sends y(Unsupported) then this is malformed message
                Self::Unsupported => 
                    scram_error!(ScramErrorCode::MalformedScramMsg,
                                "malformed message, client picked -PLUS, but did not provide cb data"),
            }
        }
        else
        {
            // -PLUS was not picked
            match *self
            {
                Self::TlsUnique | Self::TlsServerEndpoint => 
                    scram_error!(ScramErrorCode::MalformedScramMsg,
                                "client provided channel binding data while picking SCRAM without -PLUS extension!"),
                Self::None => return Ok(()),
                // client picks SCRAM-? and thinks we don't support channel binding
                Self::Unsupported => return Ok(()),
            }
        }
    }

    pub fn server_final_verify_client_cb(&self, 
                                        st: &ScramType, 
                                        cb_attr: &str,
                                        cbd: &ChannelBindingData) -> ScramResult<()>
    {
        // verify input
        //If we are not using channel binding, the binding data is expected
        // to always be "biws", which is "n,," base64-encoded, or "eSws",
        // which is "y,,".  We also have to check whether the flag is the same
        // one that the client originally sent. auth-scram_8c_source.c:1310

        match *self
        {
            Self::TlsUnique =>
            {
                panic!("assertion trap: Tls-uniq is not supported, cb_type: {}, \
                         scram_type: {}, ChannelBindingData: {}",
                        self, st, cbd)
            },
            Self::TlsServerEndpoint =>
            {
                if st.scram_chan_bind == false
                {
                    panic!("assertion trap: cb_type: {}, scram_type: {}, so when is bind==true \
                            then cb_type must be \
                            either TlsUnique or TlsServerEndpoint", 
                            self, st);
                }

                //get the data from ChannelBindingData which contains 
                //hash data of server's SSL certificate and combine it
                let header = 
                    [
                        "p=tls-server-end-point,,".as_bytes(),
                        cbd.get_endpoint_hash(),
                        //cbind_data
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
            "tls-unique" => return Ok(Self::TlsUnique),
            "tls-server-end-point" => return Ok(Self::TlsServerEndpoint),
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
