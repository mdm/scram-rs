/*-
 * Scram-rs - a SCRAM authentification authorization library
 * Copyright (C) 2021  Aleksandr Morozov
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 *  file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

pub use super::scram_sync_client::*;
pub use super::scram_sync_server::*;

#[allow(unused_imports)]
mod tests
{
    use base64::Engine;
    use base64::engine::general_purpose;

    use super::*;
    use std::num::NonZeroU32;
    use std::time::Instant;
    use crate::ChannelBindType;
    use crate::ScramAuthServer;
    use crate::ScramCbHelper;
    use crate::ScramCommon;
    use crate::ScramHashing;
    use crate::ScramNonce;
    use crate::ScramPassword;
    use crate::ScramResult;
    use crate::scram_hashing::ScramSha256RustNative;
    use crate::scram_auth::ScramAuthClient;
    use crate::scram_auth::ScramKey;
    use crate::scram_parser::ScramDataParser;
    use crate::scram_state::ScramState;

    #[test]
    fn scram_sha256_works() 
    { 
        struct AuthClient
        {
            username: String,
            password: String,
            key: ScramKey,
        }

        impl ScramAuthClient for AuthClient
        {
            fn get_username(&self) -> &str
            {
                return &self.username;
            }

            fn get_password(&self) -> &str
            {
                return &self.password;
            }

            fn get_scram_keys(&self) -> &crate::ScramKey 
            {
                return &self.key;
            }
        }

        impl ScramCbHelper for AuthClient
        {
            
        }

        impl AuthClient
        {
            pub fn new(u: &'static str, p: &'static str) -> Self
            {
                return AuthClient{username: u.to_string(), password: p.to_string(), key: ScramKey::new()};
            }
        }

        let username = "user";
        let password = "pencil";
        let client_nonce = "rOprNGfwEbeRWgbNEkqO";
        let client_nonce_dec = general_purpose::STANDARD.decode(client_nonce).unwrap();
        let client_init = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
        let server_init = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let _server_nonce = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        let _server_nonce_dec = b"\x86\xf6\x03\xa5e\x1a\xd9\x16\x93\x08\x07\xee\xc4R%\x8e\x13e\x16M";
        let client_final = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
        let server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
        
        let start = Instant::now();

        let cbt = ChannelBindType::None;

        let ac = AuthClient::new(username, password);
        let nonce = ScramNonce::Plain(&client_nonce_dec);

        let scram_res = 
            SyncScramClient::<ScramSha256RustNative, AuthClient, AuthClient>::new(&ac, nonce, cbt, &ac);
        assert_eq!(scram_res.is_ok(), true);

        let mut scram = scram_res.unwrap();
        
        let init = scram.init_client();
        assert_eq!( init.get_output().unwrap(), client_init ); 

        let resp_res = scram.parse_response(server_init);
        assert_eq!(resp_res.is_ok(), true);

        let resp = resp_res.unwrap().unwrap_output().unwrap();
        assert_eq!( resp.as_str(), client_final ); 

        let res = scram.parse_response(server_final);
        
        let el = start.elapsed();
        println!("took: {:?}", el);

        assert_eq!(res.is_ok(), true, "{}", res.err().unwrap());

        assert_eq!(scram.is_completed(), true);
    }

    #[test]
    fn scram_incorrect_test()
    {
        use std::time::Instant;
        let server_init = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        
        let start = Instant::now();
            let res = ScramDataParser::from_raw(&server_init, &ScramState::WaitForServInitMsg);
        let el = start.elapsed();
        println!("took: {:?}", el);

        assert_eq!(res.is_ok(), true);

        return;
    } 

    #[test]
    fn scram_sha256_server() 
    { 
        struct AuthServer
        {

        }

        impl ScramAuthServer<ScramSha256RustNative> for AuthServer
        {
            fn get_password_for_user(&self, _username: &str) -> ScramResult<ScramPassword>
            {
                let password = "pencil";
                let salt = b"[m\x99h\x9d\x125\x8e\xec\xa0K\x14\x126\xfa\x81".to_vec();
                let iterations = NonZeroU32::new(4096).unwrap();

                return
                    Ok(
                        ScramPassword::found_secret_password(
                            ScramSha256RustNative::derive(password.as_bytes(), &salt, iterations).unwrap(),
                            general_purpose::STANDARD.encode(salt), 
                            iterations,
                            None
                        )
                    );          
            }
        }

        impl ScramCbHelper for AuthServer
        {
            
        }

        impl AuthServer
        {
            pub fn new() -> Self
            {
                return Self{};
            }
        }


        let _username = "user";
        let _password = "pencil";
        let client_nonce = "rOprNGfwEbeRWgbNEkqO";
        let _client_nonce_dec = general_purpose::STANDARD.decode(client_nonce).unwrap();
        let client_init = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
        let server_init = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let server_nonce = "%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0";
        let _server_nonce_dec = b"\x86\xf6\x03\xa5e\x1a\xd9\x16\x93\x08\x07\xee\xc4R%\x8e\x13e\x16M".to_vec();
        let client_final = "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=";
        let server_final = "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=";
        
        let _start = Instant::now();

        let serv = AuthServer::new();
        let nonce = ScramNonce::Base64(server_nonce);
    
        let scramtype = ScramCommon::get_scramtype("SCRAM-SHA-256").unwrap();
        let scram_res = 
            SyncScramServer::<ScramSha256RustNative, AuthServer, AuthServer>::new(&serv, &serv, nonce, scramtype);
        assert_eq!(scram_res.is_ok(), true);

        let mut scram = scram_res.unwrap();

        let start = Instant::now();
        let resp_res = scram.parse_response(client_init);

        assert_eq!(resp_res.is_ok(), true);

        let resp = resp_res.get_raw_output();
        assert_eq!( resp, server_init ); 

        let resp_res = scram.parse_response(client_final);
        if resp_res.is_err() == true
        {
            println!("{}", resp_res.err().unwrap());
            assert_eq!(false, true);
            return;
        }
        
        let el = start.elapsed();
        println!("took: {:?}", el);

        let resp = resp_res.get_raw_output();
        assert_eq!( resp, server_final ); 
    }

}
