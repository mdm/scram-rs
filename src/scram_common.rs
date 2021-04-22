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

use getrandom::getrandom;

use super::scram_error::{ScramResult, ScramRuntimeError, ScramErrorCode};
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
    pub const SCRAM_DEFAULT_SALT_ITER: u32 = 4096;

    /// Generates random secuence of bytes
    /// 
    /// # Arguments
    /// 
    /// * `len` - a length of the array
    /// 
    /// # Returns
    /// 
    /// * [ScramResult] Ok - elements or Error
    pub fn sc_random(len: usize) -> ScramResult<Vec<u8>>
    {
        let mut data = Vec::<u8>::with_capacity(len);
        getrandom(&mut data)
            .map_err(|e| scram_error_map!(ScramErrorCode::ExternalError, 
                                            "getrandom err, {}", e))?;

        return Ok(data);
    }

    /// Output all supported types with separator
    pub fn adrvertise<S: AsRef<str>>(sep: S) -> String
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
    pub fn get_scramtype<S: AsRef<str>>(scram: S) -> ScramResult<&'static ScramType>
    {
        let scram_name = scram.as_ref();

        for scr_type in SCRAM_TYPES.iter()
        {
            if scr_type.scram_name == scram_name
            {
                return Ok(scr_type);
            }
        }

        scram_error!(ScramErrorCode::ExternalError,
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
    pub fn get_scramtype_numeric(scram: ScramTypeAlias) -> ScramResult<&'static ScramType>
    {
        let scram_offset = *(&scram) as usize;
        match SCRAM_TYPES.get(scram_offset)
        {
            Some(r) => return Ok(r),
            None => scram_error!(ScramErrorCode::ExternalError,
                        "unknown scram type: {:?}", scram)
        }
    }
}
