


use std::num::NonZeroU32;

use scram_rs::ScramHashing;
use scram_rs::ScramResult;
use scram_rs::ScramSha256;
use scram_rs::ScramNonce;
use scram_rs::ScramPassword;
use scram_rs::ScramAuthServer;
use scram_rs::scram_sync::SyncScramServer;
use scram_rs::ScramCommon;

struct AuthDB
{
}

impl AuthDB
{
    pub fn new() -> Self
    {
        return AuthDB{};
    }
}

impl ScramAuthServer<ScramSha256> for AuthDB
{
    fn get_password_for_user(&self, _username: &str) -> ScramResult<ScramPassword>
    {
        let password = "pencil";
        let salt = b"[m\x99h\x9d\x125\x8e\xec\xa0K\x14\x126\xfa\x81".to_vec();
        let iter = NonZeroU32::new(4096).unwrap();

        Ok(
            ScramPassword::found_secret_password(
                ScramSha256::derive(password.as_bytes(), &salt, iter).unwrap(),
                base64::encode(salt), 
                iter,
            None
            )
        )

                
    }
}

/// This example will not run, because it requires server, see tests in scram_sync.rs
pub fn main() -> ScramResult<()>
{
    let authdb = AuthDB::new();
    let scramtype = ScramCommon::get_scramtype("SCRAM-SHA-256").unwrap();

    let mut server = 
        SyncScramServer::<ScramSha256, AuthDB>::new(&authdb, None, ScramNonce::none(), scramtype).unwrap();

    let client_init = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
    let _ = server.parse_response(client_init);

    //...
    return Ok(());
}

