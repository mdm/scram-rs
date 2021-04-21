

use scram_rs::scram_error::ScramResult;
use scram_rs::scram_hashing::ScramSha256;
use scram_rs::scram_auth::ScramAuthClient;
use scram_rs::scram_cb::ClientChannelBindingType;
use scram_rs::scram::{ScramNonce, ScramClient};

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

fn mock_stream_recv() -> String
{
    return String::from("answer");
}

pub fn scram_scha256() -> ScramResult<()>
{
    // Channel binding is not required (i.e same as ChannelBinding::None)
    let cbt = ClientChannelBindingType::without_chan_binding();

    // A reference to authentification struct
    let ac = AuthClient::new("test", "testtest");

    // let lib generate nonce
    let nonce = ScramNonce::none();

    // create client instance
    let mut scram_res = ScramClient::<ScramSha256, AuthClient>::new(&ac, nonce, cbt)?;

    // get initial packet

    let initial_msg = scram_res.init_client(true);

    // send to server
    // stream.send(initial_msg);

    //receive answer
    let answer = mock_stream_recv();
    let res = scram_res.parse_response_base64(answer)?;

    let msg = res.extract_output()?;
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