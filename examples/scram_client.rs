

use scram_rs::ScramResult;
use scram_rs::ScramSha256;
use scram_rs::ScramAuthClient;
use scram_rs::ScramNonce;
use scram_rs::ClientChannelBindingType;
use scram_rs::scram_sync::SyncScramClient;

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
    pub fn new(u: &'static str, p: &'static str) -> Self
    {
        return AuthClient{username: u.to_string(), password: p.to_string(), key: scram_rs::ScramKey::new()};
    }
}

fn mock_stream_recv() -> String
{
    return String::from("answer");
}

/// This example will not run, because it requires server, see tests in scram_sync.rs
pub fn main() -> ScramResult<()>
{
    // Channel binding is not required (i.e same as ChannelBinding::None)
    let cbt = ClientChannelBindingType::without_chan_binding();

    // A reference to authentification struct
    let ac = AuthClient::new("test", "testtest");

    // let lib generate nonce
    let nonce = ScramNonce::none();

    // create client instance
    let mut scram_res = 
        SyncScramClient::<ScramSha256, AuthClient>::new(&ac, nonce, cbt)?;

    // get initial packet

    let _initial_msg = scram_res.init_client();

    // send to server
    // stream.send(initial_msg);

    //receive answer
    let answer = mock_stream_recv();
    let res = scram_res.parse_response_base64(answer)?;

    let _msg = res.unwrap_output()?;
    // send to server
    // stream.send(msg);

    //receive answer
    let answer = mock_stream_recv();

    let res = scram_res.parse_response_base64(answer)?;

    //this should be final response
    if res.is_final() == false
    {
        panic!("error! in library SCRAM-RS");
    }

    return Ok(());
}