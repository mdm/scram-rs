/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use std::fmt;
use std::num::NonZeroU32;

use getrandom::getrandom;

use crate::ScramServerError;

use super::scram_error::{ScramResult, ScramErrorCode};
use super::{scram_error, scram_error_map};

/// A numeric alias for the [SCRAM_TYPES]. If any changes were made in
/// [SCRAM_TYPES] then verify that [ScramTypeAlias] is in order.
#[repr(usize)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum ScramTypeAlias
{
    #[cfg(not(feature = "exclude_sha1"))]
    Sha1 = 0,

    Sha256 = 1,
    Sha256Plus = 2,
    Sha512 = 3,
    Sha512Plus = 4,
}

impl From<ScramTypeAlias> for usize
{
    fn from(value: ScramTypeAlias) -> Self 
    {
        return value as usize;
    }
}

/// A structured data about supported mechanisms
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct ScramType
{
    /// Scram type encoded as in RFC without trailing \r\n or \n
    pub scram_name: &'static str,

    pub scram_alias: ScramTypeAlias,

    /// Is channel binding supported (-PLUS)
    pub scram_chan_bind: bool,
}

impl PartialEq<str> for ScramType
{
    fn eq(&self, other: &str) -> bool 
    {
        return self.scram_name == other;
    }
}

impl PartialEq<ScramTypeAlias> for ScramType
{
    fn eq(&self, other: &ScramTypeAlias) -> bool 
    {
        return self.scram_alias == *other;
    }
}

impl fmt::Display for ScramType
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        write!(f, "scram: {}, channel_bind: {}", self.scram_name, self.scram_chan_bind)
    }
}

pub const SCRAM_TYPE_1: ScramType =         ScramType{scram_name:"SCRAM-SHA-1",         scram_alias: ScramTypeAlias::Sha1,          scram_chan_bind: false};
pub const SCRAM_TYPE_256: ScramType =       ScramType{scram_name:"SCRAM-SHA-256",       scram_alias: ScramTypeAlias::Sha256,        scram_chan_bind: false};
pub const SCRAM_TYPE_256_PLUS: ScramType =  ScramType{scram_name:"SCRAM-SHA-256-PLUS",  scram_alias: ScramTypeAlias::Sha256Plus,    scram_chan_bind: true};
pub const SCRAM_TYPE_512: ScramType =       ScramType{scram_name:"SCRAM-SHA-512",       scram_alias: ScramTypeAlias::Sha512,        scram_chan_bind: false};
pub const SCRAM_TYPE_512_PLUS: ScramType =  ScramType{scram_name:"SCRAM-SHA-512-PLUS",  scram_alias: ScramTypeAlias::Sha512Plus,    scram_chan_bind: true};

/// All supported SCRAM types.
#[derive(Debug, Clone)]
pub struct ScramTypes(&'static [ScramType]);

/// A table of all supported versions.
pub const SCRAM_TYPES: &'static ScramTypes = 
    &ScramTypes(
        &[
            #[cfg(not(feature = "exclude_sha1"))]
            SCRAM_TYPE_1,

            SCRAM_TYPE_256,
            SCRAM_TYPE_256_PLUS,
            SCRAM_TYPE_512,
            SCRAM_TYPE_512_PLUS,
        ]
    );

impl ScramTypes
{
    /// Creates a new table which can be used later. It also can be used to construct
    /// overrided table during compilation.
    pub const 
    fn new(table: &'static [ScramType]) -> Self
    {
        return ScramTypes(table);
    }

    /// Outputs all supported types with separator.
    /// 
    /// # Arguments
    /// 
    /// * `sep` - a [str] which should separate the output.
    /// 
    /// # Returns 
    /// 
    /// A [String] is retuned.
    pub 
    fn adrvertise<S: AsRef<str>>(&self, sep: S) -> String
    {
        return 
            self
                .0
                .iter()
                .map(|f| f.scram_name)
                .collect::<Vec<&'static str>>()
                .join(sep.as_ref());
    }

    /// Outputs all supported types to [fmt] with separator `sep`.
    pub 
    fn advertise_to_fmt<S: AsRef<str>>(&self, f: &mut fmt::Formatter, sep: S) -> fmt::Result 
    {
        for (scr_type, i) in self.0.iter().zip(0..self.0.len())
        {
            write!(f, "{}", scr_type.scram_name)?;

            if i+1 < self.0.len()
            {
                write!(f, "{}", sep.as_ref())?;
            }
        }

        return Ok(());
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
    fn get_scramtype<S: AsRef<str>>(&self, scram: S) -> ScramResult<&'static ScramType>
    {
        let scram_name = scram.as_ref();

        for scr_type in self.0.iter()
        {
            if scr_type == scram_name
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
    fn get_scramtype_numeric(&self, scram: ScramTypeAlias) -> ScramResult<&'static ScramType>
    {
        // binary search would be faster, but the list should be strictly sorted!.

        for scr_type in self.0.iter()
        {
            if scr_type == &scram
            {
                return Ok(scr_type);
            }
        }

        scram_error!(ScramErrorCode::ExternalError, ScramServerError::OtherError,
            "unknown scram type: {:?}", scram);
    }
}


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

#[cfg(test)]
mod tests
{
    use std::time::Instant;

    use crate::{ScramCommon, ScramResult, ScramTypeAlias, SCRAM_TYPES};

    #[test]
    fn sanitize_unicode()
    {
        let res = ScramCommon::sanitize_str_unicode("る\n\0bp234");

        assert_eq!(res.as_str(), "る\\x0a\\x00bp234");
    }

    #[test]
    fn test_scram_types()
    {
        let start = Instant::now();
        #[cfg(not(feature = "exclude_sha1"))]
        assert_eq!(
            SCRAM_TYPES.adrvertise(", "), 
            "SCRAM-SHA-1, SCRAM-SHA-256, SCRAM-SHA-256-PLUS, SCRAM-SHA-512, SCRAM-SHA-512-PLUS"
        );

        #[cfg(feature = "exclude_sha1")]
        assert_eq!(
            SCRAM_TYPES.adrvertise(", "), 
            "SCRAM-SHA-256, SCRAM-SHA-256-PLUS, SCRAM-SHA-512, SCRAM-SHA-512-PLUS"
        );
        let el = start.elapsed();
        println!("took: {:?}", el);

        // --
        let mut ind = 0;

        let start = Instant::now();
        #[cfg(not(feature = "exclude_sha1"))]
        assert_eq!(
            SCRAM_TYPES.get_scramtype("SCRAM-SHA-1"),
            ScramResult::Ok(&SCRAM_TYPES.0[ind])
        );

        #[cfg(not(feature = "exclude_sha1"))]
        {
            ind += 1;
        }

        let el = start.elapsed();
        println!("took: {:?}", el);

        let start = Instant::now();
        assert_eq!(
            SCRAM_TYPES.get_scramtype("SCRAM-SHA-256"),
            ScramResult::Ok(&SCRAM_TYPES.0[ind])
        );
        let el = start.elapsed();
        println!("took: {:?}", el);

        ind += 1;

        let start = Instant::now();
        assert_eq!(
            SCRAM_TYPES.get_scramtype("SCRAM-SHA-256-PLUS"),
            ScramResult::Ok(&SCRAM_TYPES.0[ind])
        );
        let el = start.elapsed();
        println!("took: {:?}", el);

        ind += 1;

        let start = Instant::now();
        assert_eq!(
            SCRAM_TYPES.get_scramtype("SCRAM-SHA-512"),
            ScramResult::Ok(&SCRAM_TYPES.0[ind])
        );
        let el = start.elapsed();
        println!("took: {:?}", el);

        ind += 1;

        assert_eq!(
            SCRAM_TYPES.get_scramtype("SCRAM-SHA-512-PLUS"),
            ScramResult::Ok(&SCRAM_TYPES.0[ind])
        );

        // -- 

        ind = 0;

        let start = Instant::now();
        #[cfg(not(feature = "exclude_sha1"))]
        assert_eq!(
            SCRAM_TYPES.get_scramtype_numeric(ScramTypeAlias::Sha1),
            ScramResult::Ok(&SCRAM_TYPES.0[0])
        );

        #[cfg(not(feature = "exclude_sha1"))]
        {
            ind += 1;
        }
        let el = start.elapsed();
        println!("took: {:?}", el);

        let start = Instant::now();
        assert_eq!(
            SCRAM_TYPES.get_scramtype_numeric(ScramTypeAlias::Sha256),
            ScramResult::Ok(&SCRAM_TYPES.0[ind])
        );
        let el = start.elapsed();
        println!("took: {:?}", el);

        ind += 1;

        let start = Instant::now();
        assert_eq!(
            SCRAM_TYPES.get_scramtype_numeric(ScramTypeAlias::Sha256Plus),
            ScramResult::Ok(&SCRAM_TYPES.0[ind])
        );
        let el = start.elapsed();
        println!("took: {:?}", el);

        ind += 1;

        assert_eq!(
            SCRAM_TYPES.get_scramtype_numeric(ScramTypeAlias::Sha512),
            ScramResult::Ok(&SCRAM_TYPES.0[ind])
        );

        ind += 1;
        assert_eq!(
            SCRAM_TYPES.get_scramtype_numeric(ScramTypeAlias::Sha512Plus),
            ScramResult::Ok(&SCRAM_TYPES.0[ind])
        );
    }
}
