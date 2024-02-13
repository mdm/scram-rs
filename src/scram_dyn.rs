/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

use async_trait::async_trait;

use crate::ScramResultServer;

/// A trait for the Server which can be used to convert the instance 
/// into the dyn Object in order to store it in the list as a generalized 
/// instance.
pub trait ScramServerDyn
{
    fn get_auth_username(&self) -> Option<&String>;
    fn parse_response_base64(&mut self, input: &[u8]) -> ScramResultServer;
    fn parse_response(&mut self, resp: &str) -> ScramResultServer;
}

/// A trait for the Server which can be used to convert the instance 
/// into the dyn Object in order to store it in the list as a generalized 
/// instance.
#[async_trait]
pub trait AsyncScramServerDyn: Send
{
    fn get_auth_username(&self) -> Option<&String>;
    async fn parse_response_base64(&mut self, input: &[u8]) -> ScramResultServer;
    async fn parse_response(&mut self, resp: &str) -> ScramResultServer;
}

pub trait ScramClientDyn
{

}

/*
pub struct ScramServerDynHolder<'ss>
{
    obj: Box<dyn ScramServerDyn + 'ss>,
}

impl<'ss> ScramServerDynHolder<'ss>
{
    pub 
    fn new(obj: Box<dyn ScramServerDyn + 'ss>) -> Self
    {
        return Self{ obj: obj };
    }
}
*/
