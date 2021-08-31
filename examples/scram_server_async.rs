

use scram_rs::async_trait;
use scram_rs::ScramHashing;
use scram_rs::ScramResult;
use scram_rs::ScramSha256;
use scram_rs::ScramNonce;
use scram_rs::ScramPassword;
use scram_rs::AsyncScramAuthServer;
use scram_rs::scram_async::AsyncScramServer;
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

#[async_trait]
impl AsyncScramAuthServer<ScramSha256> for AuthDB
{
    async fn get_password_for_user(&self, _username: &str) -> ScramResult<ScramPassword>
    {
        let password = "pencil";
        let salt = b"[m\x99h\x9d\x125\x8e\xec\xa0K\x14\x126\xfa\x81".to_vec();

        Ok(ScramPassword::found_secret_password(
                ScramSha256::derive(password.as_bytes(), &salt, 4096).unwrap(),
                base64::encode(salt), 
                4096))

                
    }
}

/// This example will not run, because it requires server, see tests in scram_async.rs
pub fn main() -> ScramResult<()>
{
    let authdb = AuthDB::new();
    let scramtype = ScramCommon::get_scramtype("SCRAM-SHA-256").unwrap();

    let mut server = 
        AsyncScramServer::<ScramSha256, AuthDB>::new(&authdb, None, ScramNonce::none(), scramtype).unwrap();

    let client_init = "n,,n=user,r=rOprNGfwEbeRWgbNEkqO";
    let _ = 
        tokio_test::block_on(async {server.parse_response(client_init, false).await});

    //...
    return Ok(());
}

