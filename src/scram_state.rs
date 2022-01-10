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

/// Order:
/// Client init: InitClient
/// Server init: WaitForClientInitalMsg
/// 
/// Client sends data and sets state: WaitForSevInitMsg
/// Server receives data and changes state to: WaitForClientFinalMsg
/// 
/// Client sends final response and sets state: WaitFinalStageFromServ
/// Server receives data and sends response and sets: Complete
/// 
/// Client receives and sets its state to: Complete
#[derive(Eq, PartialEq, Clone, Debug)]
pub(crate) enum ScramState 
{    
    /// Instance of client was created, but no comm yet initialized
    InitClient,    

    /// Client waits for the first response, after it sends initial data
    WaitForServInitMsg, 

    /// Client waits for the last response from server
    WaitForServFinalMsg{server_signature: Vec<u8>}, 

    /// Server is rready to accept first message from server
    WaitForClientInitalMsg, 

    /// Server has sent initial response to client, args: client_nonce: String
    WaitForClientFinalMsg{client_nonce: String},
    
    /// Server has sent second anser
    /// Completed: for client, 3rd response received
    /// for server, the last response was sent
    Completed,
}

impl fmt::Display for ScramState
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        match *self 
        {
            Self::InitClient                => write!(f, "InitClient"),
            Self::WaitForServInitMsg        => write!(f, "WaitForServInitMsg"),
            Self::WaitForServFinalMsg{..}   => write!(f, "WaitForServFinalMsg"),
            Self::WaitForClientInitalMsg    => write!(f, "WaitForClientInitalMsg"),
            Self::WaitForClientFinalMsg{..} => write!(f, "WaitForClientFinalMsg"),
            Self::Completed                 => write!(f, "Completed"),
        }
    }
}

/*impl fmt::Debug for ScramState
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result 
    {
        match *self 
        {
            Self::InitClient                => write!(f, "InitClient"),
            Self::WaitForServInitMsg        => write!(f, "WaitForServInitMsg"),
            Self::WaitForServFinalMsg{..}   => write!(f, "WaitForServFinalMsg"),
            Self::WaitForClientInitalMsg    => write!(f, "WaitForClientInitalMsg"),
            Self::WaitForClientFinalMsg{..} => write!(f, "WaitForClientFinalMsg"),
            Self::Completed                 => write!(f, "Completed"),
        }
    }
}*/