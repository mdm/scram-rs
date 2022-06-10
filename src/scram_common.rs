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
use std::num::NonZeroU32;

use getrandom::getrandom;

use crate::{ScramServerError};

use super::scram_error::{ScramResult, ScramErrorCode};
use super::{scram_error, scram_error_map};

/// A numeric alias for the [SCRAM_TYPES]. If any changes were made in
/// [SCRAM_TYPES] then verify that [ScramTypeAlias] is in order.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ScramTypeAlias
{
    Sha1 = 0,
    Sha256 = 1,
    Sha256Plus = 2,
    Sha512 = 3,
    Sha512Plus = 4,
}

/// A structured data about supported mechanisms
#[derive(Debug, PartialEq)]
pub struct ScramType
{
    /// Scram type encoded as in RFC without trailing \r\n or \n
    pub scram_name: &'static str,

    /// Is channel binding supported (-PLUS)
    pub scram_chan_bind: bool,
}


impl fmt::Display for ScramType
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        write!(f, "scram: {}, channel_bind: {}", self.scram_name, self.scram_chan_bind)
    }
}

/// A table of all supported versions.
pub const SCRAM_TYPES: &'static [ScramType] = 
&[
    ScramType{scram_name:"SCRAM-SHA-1",         scram_chan_bind: false}, 
    ScramType{scram_name:"SCRAM-SHA-256",       scram_chan_bind: false},
    ScramType{scram_name:"SCRAM-SHA-256-PLUS",  scram_chan_bind: true},
    ScramType{scram_name:"SCRAM-SHA-512",       scram_chan_bind: false},
    ScramType{scram_name:"SCRAM-SHA-512-PLUS",  scram_chan_bind: true},
];

pub struct ScramCommon{}
impl ScramCommon
{
    /// A default raw (non base64) nonce length
    pub const SCRAM_RAW_NONCE_LEN: usize = 32;

    /// A mock salt default len
    pub const MOCK_AUTH_NONCE_LEN: usize = 16;

    /// Default HMAC iterations
    pub const SCRAM_DEFAULT_SALT_ITER: NonZeroU32 = unsafe { NonZeroU32::new_unchecked(4096) };

    pub const SCRAM_MAX_ITERS: u32 = 999999999;

    /// Generates random secuence of bytes
    /// 
    /// # Arguments
    /// 
    /// * `len` - a length of the array
    /// 
    /// # Returns
    /// 
    /// * [ScramResult] Ok - elements or Error
    pub 
    fn sc_random(len: usize) -> ScramResult<Vec<u8>>
    {
        let mut data = Vec::<u8>::with_capacity(len);
        
        getrandom(&mut data)
            .map_err(|e| 
                scram_error_map!(ScramErrorCode::ExternalError, ScramServerError::OtherError, "scram getrandom err, {}", e)
            )?;

        return Ok(data);
    }

    /// Output all supported types with separator
    pub 
    fn adrvertise<S: AsRef<str>>(sep: S) -> String
    {
        let mut scram_adv: Vec<&str> = Vec::with_capacity(SCRAM_TYPES.len());

        for scr_type in SCRAM_TYPES.iter()
        {
            scram_adv.push(scr_type.scram_name);
        }

        return scram_adv.join(sep.as_ref());
    }

    /// Retrieves the SCRAM type by name which are hardcoded in [SCRAM_TYPES] 
    /// i.e SCRAM-SHA256.
    /// 
    /// # Arguments
    /// 
    /// * `scram` - a scram auth type
    /// 
    /// # Returns
    /// 
    /// * [ScramResult] - a reference to record from table with static lifetime
    ///                     or Error [ScramErrorCode::ExternalError] if not found
    pub 
    fn get_scramtype<S: AsRef<str>>(scram: S) -> ScramResult<&'static ScramType>
    {
        let scram_name = scram.as_ref();

        for scr_type in SCRAM_TYPES.iter()
        {
            if scr_type.scram_name == scram_name
            {
                return Ok(scr_type);
            }
        }

        scram_error!(ScramErrorCode::ExternalError, ScramServerError::OtherError, 
            "unknown scram type: {}", scram_name);
    }

    /// Retrieves the SCRAM type from [SCRAM_TYPES] by the numeric alias which 
    /// are hardcoded in [ScramTypeAlias] 
    /// i.e SCRAM-SHA256.
    /// 
    /// # Arguments
    /// 
    /// * `scram` - a scram numeric auth type [ScramTypeAlias]
    /// 
    /// # Returns
    /// 
    /// * [ScramResult] - a reference to record from table with static lifetime
    ///                     or Error [ScramErrorCode::ExternalError] if not found
    pub 
    fn get_scramtype_numeric(scram: ScramTypeAlias) -> ScramResult<&'static ScramType>
    {
        let scram_offset = *(&scram) as usize;
        
        match SCRAM_TYPES.get(scram_offset)
        {
            Some(r) => return Ok(r),
            None => scram_error!(ScramErrorCode::ExternalError, ScramServerError::OtherError,
                "unknown scram type: {:?}", scram)
        }
    }
}

impl ScramCommon
{
    pub(crate)
    fn sanitize_char(c: char) -> String
    {
        if c.is_ascii_graphic() == true
        {
            return c.to_string();
        }
        else
        {
            let mut buf = [0_u8; 4];
                c.encode_utf8(&mut buf);

            let formatted: String = 
                buf[0..c.len_utf8()].into_iter()
                    .map(|c| format!("\\x{:02x}", c))
                    .collect();

            return formatted;
        }
    }

    pub(crate)
    fn sanitize_str(st: &str) -> String
    {
        let mut out = String::with_capacity(st.len());

        for c in st.chars()
        {
            if c.is_ascii_alphanumeric() == true ||
                c.is_ascii_punctuation() == true ||
                c == ' '
            {
                out.push(c);
            }
            else
            {
                let mut buf = [0_u8; 4];
                c.encode_utf8(&mut buf);

                let formatted: String = 
                    buf[0..c.len_utf8()].into_iter()
                        .map(|c| format!("\\x{:02x}", c))
                        .collect();

                out.push_str(&formatted);
            }
        }

        return out;
    }

    pub(crate)
    fn sanitize_str_unicode(st: &str) -> String
    {
        let mut out = String::with_capacity(st.len());

        for c in st.chars()
        {
            if c.is_alphanumeric() == true ||
                c.is_ascii_punctuation() == true ||
                c == ' '
            {
                out.push(c);
            }
            else
            {
                let mut buf = [0_u8; 4];
                c.encode_utf8(&mut buf);

                let formatted: String = 
                    buf[0..c.len_utf8()].into_iter()
                        .map(|c| format!("\\x{:02x}", c))
                        .collect();

                out.push_str(&formatted);
            }
        }

        return out;
    }
}

#[test]
fn sanitize_unicode()
{
    let res = ScramCommon::sanitize_str_unicode("る\n\0bp234");

    assert_eq!(res.as_str(), "る\\x0a\\x00bp234");
}
