/*-
* RsScram
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

use getrandom::getrandom;

use super::scram_error::{ScramResult, ScramRuntimeError, ScramErrorCode};
use super::{scram_error, scram_error_map};

pub struct ScramCommon{}
impl ScramCommon
{
    pub const SCRAM_RAW_NONCE_LEN: usize = 32;
    pub const MOCK_AUTH_NONCE_LEN: usize = 16;
    pub const SCRAM_DEFAULT_SALT_ITER: u32 = 4096;

    pub fn sc_random(len: usize) -> ScramResult<Vec<u8>>
    {
        let mut data = Vec::<u8>::with_capacity(len);
        getrandom(&mut data).map_err(|e| scram_error_map!(ScramErrorCode::ExternalError, 
                                                        "getrandom err, {}", e))?;

        return Ok(data);
    }
}
