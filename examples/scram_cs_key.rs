
use std::num::NonZeroU32;

use std::sync::mpsc::channel;
use std::thread;

use scram_rs::ScramAuthClient;
use scram_rs::ScramKey;
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
        let mut sk = ScramKey::new();
        sk.set_server_key(b"testkey123456".to_vec());
        sk.set_client_key(b"keytest123456".to_vec());
        
        return 
            Ok(ScramPassword::found_secret_base64_password(
                "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o=".to_string(),
                    "c2FsdA==".to_string(), 
                    unsafe { NonZeroU32::new_unchecked(4096) },
                Some(sk)
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
        let mut sk = ScramKey::new();
        sk.set_server_key(b"testkey123456".to_vec());
        sk.set_client_key(b"keytest123456".to_vec());

        return AuthClient{ username: u.to_string(), password: p.to_string(), key: sk };
    }
}

/// This example will not run, because it requires server, see tests in scram_sync.rs
pub fn main() -> ScramResult<()>
{
    
    let authdb = AuthDB::new();
    let scramtype = ScramCommon::get_scramtype("SCRAM-SHA-256").unwrap();

    let mut server = 
        SyncScramServer::<ScramSha256, AuthDB>::new(&authdb, None, ScramNonce::none(), scramtype).unwrap();

    
    let (client_send, server_recv) = channel::<String>();
    let (server_send, client_recv) = channel::<String>();

    // spawn client
    let thr = 
        thread::spawn(move || 
            {
                let client_auth = AuthClient::new("user", "password");

                let mut client =
                    SyncScramClient::<ScramSha256, AuthClient>::new(&client_auth, ScramNonce::None, scram_rs::ClientChannelBindingType::None).unwrap();


                let ci = client.init_client().encode_output_base64().unwrap();
                client_send.send(ci).unwrap();

                loop
                {
                    let rcv = client_recv.recv().unwrap();

                    let ci1 = client.parse_response_base64(&rcv).unwrap();

                    if ci1.is_final() == true
                    {
                        println!("auth success, CLIENT");
                        

                        return;
                    }
                    else
                    {
                        client_send.send(ci1.encode_output_base64().unwrap()).unwrap();
                    }
                }
            }
        );

    loop
    {
        let rcv = server_recv.recv().unwrap();

        let si = server.parse_response_base64(&rcv).unwrap();

        server_send.send(si.encode_base64()).unwrap();

        if si.is_completed() == true
        {
            println!("auth success, SERVER");

            thr.join().unwrap();

            return Ok(());
        }
    }
}
