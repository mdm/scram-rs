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

#[derive(PartialEq, Clone)]
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

impl fmt::Debug for ScramState
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