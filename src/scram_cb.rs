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

use super::scram_common::ScramType;
use super::scram_error::{ScramResult, ScramRuntimeError, ScramErrorCode};
use super::{scram_error};

/// A channel binding type picked by client.
pub(crate) enum ServerChannelBindType
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

impl fmt::Display for ServerChannelBindType
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

impl ServerChannelBindType
{
    /// Initializes enum as n,,
    pub fn n() -> Self
    {
        return Self::None;
    }

    /// Initializes enum as y,,
    pub fn y() -> Self
    {
        return Self::Unsupported;
    }

    /// Initializes enum as p=tls-server-end-point
    #[allow(dead_code)]
    pub fn tls_server_endpoint() -> Self
    {
        return Self::TlsServerEndpoint;
    }

    /// Verifies the client initial request about the Channel Bind
    /// If client picks SCRAM-? without -PLUS extension, then it should not
    /// require any channel binding i.e n -(None) or y-(Unsupported)
    /// 
    /// # Arguments
    /// 
    /// * `st` - picked SCRAM type
    /// 
    /// # Returns
    /// 
    /// * [ScramResult] - returns nothing in payload or error
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

                Self::TlsServerEndpoint{..} => return Ok(()),

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
                Self::TlsUnique | Self::TlsServerEndpoint{..} => 
                    scram_error!(ScramErrorCode::MalformedScramMsg,
                                "client provided channel binding data while picking SCRAM without -PLUS extension!"),
                Self::None => return Ok(()),
                // client picks SCRAM-? and thinks we don't support channel binding
                Self::Unsupported => return Ok(()),
            }
        }
    }

    /// Server uses this function to verify the the client channel bind
    /// in final message.
    /// 
    /// # Arguments
    /// 
    /// * `st` - [ScramType] a current scram type
    /// 
    /// * `cb_attr` - a received channel binding data from client in base64 format
    /// 
    /// * `endpoint_hash` - a servers TLS end point certificate
    /// 
    /// # Returns
    /// 
    /// * [ScramResult] nothing in payload or error
    pub fn server_final_verify_client_cb(&mut self, 
                                        st: &ScramType, 
                                        cb_attr: &str,
                                        endpoint_hash: Option<&std::vec::Vec<u8>>) -> ScramResult<()>
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
                         scram_type: {}",
                        self, st)
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

                let endp_cert_hash = match endpoint_hash
                    {
                        Some(r) => r,   
                        None => panic!("assertion trap: cb_type: {}, scram_type: {} \
                                        TlsServerEndpoint requires endpoint_hash to be Some(...)", 
                                        self, st)
                    };
                //get the data from ChannelBindingData which contains 
                //hash data of server's SSL certificate and combine it
                let header = 
                    [
                        "p=tls-server-end-point,,".as_bytes(),
                        endp_cert_hash,
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

    /// Converts channel binding type directly from string, for server side use only
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

    #[allow(dead_code)]
    pub fn convert2header(&self) -> &[u8]
    {
        match self
        {
            Self::None => return b"n,,",
            Self::Unsupported => return b"y,,",
            Self::TlsUnique => panic!("not supported yet"), //"p=tls-unique,,"
            Self::TlsServerEndpoint{..} => b"p=tls-server-end-point,,"
        }
    }
}

/// Sets the channel bind type
pub enum ClientChannelBindingType
{
    /// No channel binding data.
    None,
    /// Advertise that the client does not think the server supports channel binding.
    Unsupported,
    /// p=tls-unique channel binding data. Not supported
    //TlsUnique,
    /// p=tls-server-end-point
    TlsServerEndpoint{cb_data: Vec<u8>},
}

impl fmt::Display for ClientChannelBindingType
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        match *self 
        {
            Self::None => write!(f, "None"),
            Self::Unsupported => write!(f, "Unsupported"),
            //Self::TlsUnique => write!(f, "TlsUnique"),
            Self::TlsServerEndpoint{..} => write!(f, "TlsServerEndpoint"),
        }
    }
}

impl ClientChannelBindingType
{
    /// Initializes enum as No channel binding is required
    pub fn without_chan_binding() -> Self
    {
        return Self::None;
    }

    /// Initializes enum as Client picks -PLUS and provides the endpoint cert hash
    pub fn with_tls_server_endpoint(cb_data: Vec<u8>) -> Self
    {
        return Self::TlsServerEndpoint{cb_data: cb_data};
    }

    /// Converts the [ClientChannelBindingType] to protocol header text 
    pub fn convert2header(&self) -> &[u8]
    {
        match self
        {
            Self::None => return b"n,,",
            Self::Unsupported => return b"y,,",
            //Self::TlsUnique => panic!("not supported yet"), //"p=tls-unique,,"
            Self::TlsServerEndpoint{..} => b"p=tls-server-end-point,,"
        }
    }

    // Extracts from the [ClientChannelBindingType] the stored data
    pub fn convert2data(&self) -> &[u8]
    {
        match *self
        {
            Self::None => return b"",
            Self::Unsupported => return b"",
            //Self::TlsUnique => panic!("not supported yet"),
            Self::TlsServerEndpoint{ref cb_data} => 
            {
                cb_data
            }
        }
    }
}
