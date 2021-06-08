
use scram_rs::async_trait;
use scram_rs::ScramResult;
use scram_rs::ScramSha256;
use scram_rs::AsyncScramAuthClient;
use scram_rs::ScramNonce;
use scram_rs::ClientChannelBindingType;
use scram_rs::scram_async::AsyncScramClient;

struct AuthClient
{
    username: String,
    password: String,
}

#[async_trait]
impl AsyncScramAuthClient for AuthClient
{
    async fn get_username(&self) -> &String
    {
        return &self.username;
    }

    async fn get_password(&self) -> &String
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

/// This example will not run, because it requires server, see tests in scram_async.rs
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
        AsyncScramClient::<ScramSha256, AuthClient>::new(&ac, nonce, cbt)?;

    // get initial packet

    let _initial_msg = 
        tokio_test::block_on(async {scram_res.init_client(true).await});

    // send to server
    // stream.send(initial_msg);

    //receive answer
    let answer = mock_stream_recv();
    let res = 
        tokio_test::block_on(async {scram_res.parse_response_base64(answer).await});

    let _msg = res.unwrap().extract_output();
    // send to server
    // stream.send(msg);

    //receive answer
    let answer = mock_stream_recv();

    let res = 
        tokio_test::block_on(async {scram_res.parse_response_base64(answer).await});

    //this should be final response
    if res.unwrap().is_final() == false
    {
        panic!("error! in library SCRAM-RS");
    }

    return Ok(());
}