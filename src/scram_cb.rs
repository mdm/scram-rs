/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov, RELKOM s.r.o
 * Copyright (C) 2021-2022  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::fmt;

use crate::scram_cbh::{ScramCbHelper, AsyncScramCbHelper};
use crate::{ScramServerError};

use super::scram_common::ScramType;
use super::scram_error::{ScramResult, ScramErrorCode};
use super::{scram_error};

/// A channel binding type picked by client.
pub enum ChannelBindType
{
    /// No channel binding data.
    None,
    /// Advertise that the client does not think the server supports channel binding.
    Unsupported,
    /// p=tls-unique channel binding data.
    TlsUnique,
    /// p=tls-server-end-point
    TlsServerEndpoint,
    /// p=tls-exporter
    TlsExporter,
}

impl fmt::Display for ChannelBindType
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        match *self 
        {
            Self::None => write!(f, "None"),
            Self::Unsupported => write!(f, "Unsupported"),
            Self::TlsUnique => write!(f, "TlsUnique"),
            Self::TlsServerEndpoint => write!(f, "TlsServerEndpoint"),
            Self::TlsExporter => write!(f, "TlsExporter"),
        }
    }
}

impl ChannelBindType
{
    /// Initializes enum as n,,
    pub 
    fn n() -> Self
    {
        return Self::None;
    }

    /// Initializes enum as y,,
    pub 
    fn y() -> Self
    {
        return Self::Unsupported;
    }

    /// Initializes enum as p=tls-server-end-point
    pub 
    fn tls_server_endpoint() -> Self
    {
        return Self::TlsServerEndpoint;
    }

    /// Initializes enum as p=tls-unique
    pub 
    fn tls_unique() -> Self
    {
        return Self::TlsUnique;
    }

    /// Initializes p=tls-exporter
    pub 
    fn tls_exporter() -> Self
    {
        return Self::TlsExporter;
    }

    /// Converts the enum [ChannelBindType] to protocol header text 
    pub 
    fn convert2header(&self) -> &str
    {
        match self
        {
            Self::None => return "n,,",
            Self::Unsupported => return "y,,",
            Self::TlsUnique => "p=tls-unique,,",
            Self::TlsServerEndpoint => "p=tls-server-end-point,,",
            Self::TlsExporter => "p=tls-exporter,,",
        }
    }
 
    pub 
    fn get_cb_data_raw(&self, sbh: &dyn ScramCbHelper) -> ScramResult<Vec<u8>>
    {
        match self
        {
            Self::None => return Ok(b"".to_vec()),
            Self::Unsupported => return Ok(b"".to_vec()),
            Self::TlsUnique => sbh.get_tls_unique(),
            Self::TlsServerEndpoint => sbh.get_tls_server_endpoint(),
            Self::TlsExporter => sbh.get_tls_exporter(),
        }
    }

    pub async 
    fn async_get_cb_data_raw(&self, sbh: &dyn AsyncScramCbHelper) -> ScramResult<Vec<u8>>
    {
        match self
        {
            Self::None => return Ok(b"".to_vec()),
            Self::Unsupported => return Ok(b"".to_vec()),
            Self::TlsUnique => sbh.get_tls_unique().await,
            Self::TlsServerEndpoint => sbh.get_tls_server_endpoint().await,
            Self::TlsExporter => sbh.get_tls_exporter().await,
        }
    }

    /// Verifies the client initial request of the Channel Bind type
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
    pub 
    fn server_initial_verify_client_cb(&self, st: &ScramType) -> ScramResult<()>
    {
        if st.scram_chan_bind == true
        {
            // server with channel binding support
            match *self
            {
                Self::TlsUnique => return Ok(()),

                Self::TlsServerEndpoint => return Ok(()),

                Self::TlsExporter => return Ok(()),

                Self::None => 
                    scram_error!(
                        ScramErrorCode::MalformedScramMsg,
                        ScramServerError::ChannelBindingsDontMatch,
                        "malformed message, client selected *-PLUS but message did not include cb data!"
                    ),

                //if client pickes -PLUS and sends y(Unsupported) then this is malformed message
                Self::Unsupported => 
                    scram_error!(
                        ScramErrorCode::MalformedScramMsg,
                        ScramServerError::ChannelBindingsDontMatch,
                        "malformed message, client picked -PLUS, but did not provide cb data"
                    ),
            }
        }
        else
        {
            // -PLUS was not picked
            match *self
            {
                Self::TlsUnique | Self::TlsServerEndpoint | Self::TlsExporter => 
                    scram_error!(
                        ScramErrorCode::MalformedScramMsg,
                        ScramServerError::ChannelBindingsDontMatch,
                        "client provided channel binding data while picking SCRAM without -PLUS extension!"
                    ),

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
    pub 
    fn server_final_verify_client_cb(
        &self, 
        st: &ScramType, 
        cb_attr: &str,
        sbh: &dyn ScramCbHelper,
    ) -> ScramResult<()>
    {
        // verify input
        // If we are not using channel binding, the binding data is expected
        // to always be "biws", which is "n,," base64-encoded, or "eSws",
        // which is "y,,".  We also have to check whether the flag is the same
        // one that the client originally sent. auth-scram_8c_source.c:1310

        let comp_cb_attr = 
            match *self
            {
                Self::TlsExporter => 
                {
                    if st.scram_chan_bind == false
                    {
                        scram_error!(
                            ScramErrorCode::InternalError,
                            ScramServerError::OtherError,
                            "assertion trap: cb_type: {}, scram_type: {}, does not \
                                include SCRAM channel binding",
                            self, st
                        );
                    }

                    let expt_tls = 
                        match sbh.get_tls_exporter()
                        {
                            Ok(r) => r,   
                            Err(e) => 
                                scram_error!(
                                    ScramErrorCode::InternalError,
                                    ScramServerError::OtherError,
                                    "assertion trap: cb_type: {}, scram_type: {} \
                                    TlsExporter requires endpoint data from TLS connection! \
                                    Error returned: '{}'", 
                                    self, st, e
                                ),
                        };

                    let header = 
                        [
                            self.convert2header().as_bytes(), //"p=tls-server-end-point,,".as_bytes(),
                            expt_tls.as_slice(),
                            //cbind_data
                        ].concat();
                    
                    let bheader = base64::encode(header);
                    
                    bheader
                },
                Self::TlsUnique =>
                {
                    if st.scram_chan_bind == false
                    {
                        scram_error!(
                            ScramErrorCode::InternalError,
                            ScramServerError::OtherError,
                            "assertion trap: cb_type: {}, scram_type: {}, does not \
                                include SCRAM channel binding",
                            self, st
                        );
                    }

                    let uniq_tls = 
                        match sbh.get_tls_unique()
                        {
                            Ok(r) => r,   
                            Err(e) => 
                                scram_error!(
                                    ScramErrorCode::InternalError,
                                    ScramServerError::OtherError,
                                    "assertion trap: cb_type: {}, scram_type: {} \
                                    TlsUnique requires endpoint data from TLS connection! \
                                    Error returned: '{}'", 
                                    self, st, e
                                ),
                        };

                    let header = 
                        [
                            self.convert2header().as_bytes(), //"p=tls-server-end-point,,".as_bytes(),
                            uniq_tls.as_slice(),
                            //cbind_data
                        ].concat();
                    
                    let bheader = base64::encode(header);
                    
                    bheader
                },
                Self::TlsServerEndpoint =>
                {
                    if st.scram_chan_bind == false
                    {
                        scram_error!(
                            ScramErrorCode::InternalError,
                            ScramServerError::OtherError,
                            "assertion trap: cb_type: {}, scram_type: {}, does not \
                                include SCRAM channel binding",
                            self, st
                        );
                    }

                    let endp_cert_hash = 
                        match sbh.get_tls_server_endpoint()
                        {
                            Ok(r) => r,   
                            Err(e) => 
                                scram_error!(
                                    ScramErrorCode::InternalError,
                                    ScramServerError::OtherError,
                                    "assertion trap: cb_type: {}, scram_type: {} \
                                    TlsServerEndpoint requires endpoint data from TLS connection! \
                                    Error returned: '{}'", 
                                    self, st, e
                                ),
                        };

                    //get the data from ChannelBindingData which contains 
                    //hash data of server's SSL certificate and combine it
                    let header = 
                        [
                            self.convert2header().as_bytes(), //"p=tls-server-end-point,,".as_bytes(),
                            endp_cert_hash.as_slice(),
                            //cbind_data
                        ].concat();
                    
                    let bheader = base64::encode(header);


                    bheader
                },
                Self::Unsupported => 
                {
                    "eSws".to_string()
                },
                Self::None =>
                {
                    "biws".to_string()
                }
            };

        if comp_cb_attr.as_str() == cb_attr
        {
            return Ok(());
        }
        else
        {
            scram_error!(
                ScramErrorCode::VerificationError, 
                ScramServerError::OtherError,
                "SCRAM channel binding '{}' check failed! Scram type: {}",
                self, st
            );
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
    pub async 
    fn async_server_final_verify_client_cb(
        &self, 
        st: &ScramType, 
        cb_attr: &str,
        sbh: &(dyn AsyncScramCbHelper + Sync),
    ) -> ScramResult<()>
    {
        // verify input
        // If we are not using channel binding, the binding data is expected
        // to always be "biws", which is "n,," base64-encoded, or "eSws",
        // which is "y,,".  We also have to check whether the flag is the same
        // one that the client originally sent. auth-scram_8c_source.c:1310

        let comp_cb_attr = 
            match *self
            {
                Self::TlsExporter => 
                {
                    if st.scram_chan_bind == false
                    {
                        scram_error!(
                            ScramErrorCode::InternalError,
                            ScramServerError::OtherError,
                            "assertion trap: cb_type: {}, scram_type: {}, does not \
                                include SCRAM channel binding",
                            self, st
                        );
                    }

                    let expt_tls = 
                        match sbh.get_tls_exporter().await
                        {
                            Ok(r) => r,   
                            Err(e) => 
                                scram_error!(
                                    ScramErrorCode::InternalError,
                                    ScramServerError::OtherError,
                                    "assertion trap: cb_type: {}, scram_type: {} \
                                    TlsExporter requires endpoint data from TLS connection! \
                                    Error returned: '{}'", 
                                    self, st, e
                                ),
                        };

                    let header = 
                        [
                            self.convert2header().as_bytes(), //"p=tls-server-end-point,,".as_bytes(),
                            expt_tls.as_slice(),
                            //cbind_data
                        ].concat();
                    
                    let bheader = base64::encode(header);
                    
                    bheader
                },
                Self::TlsUnique =>
                {
                    if st.scram_chan_bind == false
                    {
                        scram_error!(
                            ScramErrorCode::InternalError,
                            ScramServerError::OtherError,
                            "assertion trap: cb_type: {}, scram_type: {}, does not \
                                include SCRAM channel binding",
                            self, st
                        );
                    }

                    let uniq_tls = 
                        match sbh.get_tls_unique().await
                        {
                            Ok(r) => r,   
                            Err(e) => 
                                scram_error!(
                                    ScramErrorCode::InternalError,
                                    ScramServerError::OtherError,
                                    "assertion trap: cb_type: {}, scram_type: {} \
                                    TlsUnique requires endpoint data from TLS connection! \
                                    Error returned: '{}'", 
                                    self, st, e
                                ),
                        };

                    let header = 
                        [
                            self.convert2header().as_bytes(), //"p=tls-server-end-point,,".as_bytes(),
                            uniq_tls.as_slice(),
                            //cbind_data
                        ].concat();
                    
                    let bheader = base64::encode(header);
                    
                    bheader
                },
                Self::TlsServerEndpoint =>
                {
                    if st.scram_chan_bind == false
                    {
                        scram_error!(
                            ScramErrorCode::InternalError,
                            ScramServerError::OtherError,
                            "assertion trap: cb_type: {}, scram_type: {}, does not \
                                include SCRAM channel binding",
                            self, st
                        );
                    }

                    let endp_cert_hash = 
                        match sbh.get_tls_server_endpoint().await
                        {
                            Ok(r) => r,   
                            Err(e) => 
                                scram_error!(
                                    ScramErrorCode::InternalError,
                                    ScramServerError::OtherError,
                                    "assertion trap: cb_type: {}, scram_type: {} \
                                    TlsServerEndpoint requires endpoint data from TLS connection! \
                                    Error returned: '{}'", 
                                    self, st, e
                                ),
                        };

                    //get the data from ChannelBindingData which contains 
                    //hash data of server's SSL certificate and combine it
                    let header = 
                        [
                            self.convert2header().as_bytes(), //"p=tls-server-end-point,,".as_bytes(),
                            endp_cert_hash.as_slice(),
                            //cbind_data
                        ].concat();
                    
                    let bheader = base64::encode(header);


                    bheader
                },
                Self::Unsupported => 
                {
                    "eSws".to_string()
                },
                Self::None =>
                {
                    "biws".to_string()
                }
            };

        if comp_cb_attr.as_str() == cb_attr
        {
            return Ok(());
        }
        else
        {
            scram_error!(
                ScramErrorCode::VerificationError, 
                ScramServerError::OtherError,
                "SCRAM channel binding '{}' check failed! Scram type: {}",
                self, st
            );
        }
    }

    /// Converts channel binding type directly from string, for server side use only
    pub 
    fn from_str<C: AsRef<str>>(cb: C) -> ScramResult<Self>
    {
        match cb.as_ref()
        {
            "none" => 
                return Ok(Self::None),
            "unsupported" => 
                return Ok(Self::Unsupported),
            "tls-unique" => 
                return Ok(Self::TlsUnique),
            "tls-server-end-point" => 
                return Ok(Self::TlsServerEndpoint),
            _ => 
                scram_error!(ScramErrorCode::ProtocolViolation, ScramServerError::ChannelBindingNotSupported, 
                    "Unknown channel bind type: '{}'", cb.as_ref()),
        }
    }
}
