
use std::num::NonZeroU32;

use scram_rs::ScramAuthClient;
use scram_rs::ScramResult;
use scram_rs::ScramSha256;
use scram_rs::ScramNonce;
use scram_rs::ScramPassword;
use scram_rs::ScramAuthServer;
use scram_rs::scram_sync::SyncScramClient;
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
        return 
        Ok(ScramPassword::found_secret_base64_password(
            "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o=".to_string(),
                "c2FsdA==".to_string(), 
                unsafe { NonZeroU32::new_unchecked(4096) },
            None
        )?);

                
    }
}

struct AuthClient
{
    username: String,
    password: String,
    key: scram_rs::ScramKey,
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

    fn get_scram_keys(&self) -> &scram_rs::ScramKey 
    {
        return &self.key;
    }
}

impl AuthClient
{
    pub 
    fn new(u: &'static str, p: &'static str) -> Self
    {
        return AuthClient{ username: u.to_string(), password: p.to_string(), key: scram_rs::ScramKey::new() };
    }
}

/// This example will not run, because it requires server, see tests in scram_sync.rs
pub fn main() -> ScramResult<()>
{
    let client = AuthClient::new("user", "password");
    let authdb = AuthDB::new();
    let scramtype = ScramCommon::get_scramtype("SCRAM-SHA-256").unwrap();

    let mut server = 
        SyncScramServer::<ScramSha256, AuthDB>::new(&authdb, None, ScramNonce::none(), scramtype).unwrap();

    let mut client =
        SyncScramClient::<ScramSha256, AuthClient>::new(&client, ScramNonce::None, scram_rs::ClientChannelBindingType::None).unwrap();

    let ci = client.init_client().encode_output_base64().unwrap();
    let si = server.parse_response_base64(&ci).unwrap().encode_base64();

    let ci1 = client.parse_response_base64(&si).unwrap().encode_output_base64().unwrap();
    let si1 = server.parse_response_base64(&ci1).unwrap().encode_base64();

    if client.parse_response_base64(&si1).unwrap().is_final() == true
    {
        println!("ready!");
    }


    //...
    return Ok(());
}
