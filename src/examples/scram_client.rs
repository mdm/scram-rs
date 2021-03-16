

use scram_rs::scram_hashing::ScramSha256;
use scram_rs::scram_auth::ScramAuthClient;
use scram_rs::scram_cb::ChannelBinding;

struct AuthClient
{
    username: String,
    password: String,
}

impl ScramAuthClient for AuthClient
{
    fn get_username(&self) -> &String
    {
        return &self.username;
    }

    fn get_password(&self) -> &String
    {
        return &self.password;
    }
}

impl AuthClient
{
    pub fn new(u: &'static str, p: &'static str) -> Self
    {
        return AuthClient{username: u.to_string(), password: p.to_string()};
    }
}

pub fn scram_scha256()
{
    // Not using channel binding none (i.e same as ChannelBinding::None)
    let cbt = ChannelBinding::from_str("none").unwrap();
    
    // creating 
    let ac = AuthClient::new("username", "password");
   /* let nonce = ScramNonce::Plain(&client_nonce_dec);

    let scram_res = ScramClient::<ScramSha256, AuthClient>::new(ac, nonce, cbt);*/
}