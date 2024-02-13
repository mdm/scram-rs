
use std::num::NonZeroU32;

use scram_rs::AsyncScramAuthClient;
use scram_rs::AsyncScramAuthServer;
use scram_rs::AsyncScramCbHelper;
use scram_rs::BorrowOrConsume;
use scram_rs::ScramResult;
use scram_rs::ScramResultClient;
use scram_rs::ScramSha256RustNative;
use scram_rs::ScramNonce;
use scram_rs::ScramPassword;
use scram_rs::async_trait;
use scram_rs::scram_async::AsyncScramClient;
use scram_rs::scram_async::AsyncScramServer;
use scram_rs::ScramCommon;

#[derive(Debug)]
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

#[derive(Debug)]
struct AuthDBCb
{
}

#[async_trait]
impl AsyncScramCbHelper for AuthDBCb
{
    async 
    fn get_tls_server_endpoint(&self) -> ScramResult<Vec<u8>> 
    {
        scram_rs::HELPER_UNSUP_SERVER!("endpoint");
    }

    async 
    fn get_tls_unique(&self) -> ScramResult<Vec<u8>> {
        scram_rs::HELPER_UNSUP_SERVER!("unique");
    }
/*
    async 
    fn get_tls_exporter(&self) -> ScramResult<Vec<u8>> 
    {
        scram_rs::HELPER_UNSUP_SERVER!("exporter");
    }
    */
}



#[async_trait]
impl AsyncScramAuthServer<ScramSha256RustNative> for AuthDB
{
    async 
    fn get_password_for_user(&self, username: &str) -> ScramResult<ScramPassword>
    {
        return 
            if username == "user"
            {
                Ok(ScramPassword::found_secret_base64_password(
                    "xeR41ZKIyEGqUw22hFxMjZYok6ABzk4RpJY4c6qYE0o=".to_string(),
                        "c2FsdA==".to_string(), 
                        unsafe { NonZeroU32::new_unchecked(4096) },
                    None
                )?)
            }
            else 
            {
                ScramPassword::not_found::<ScramSha256RustNative>()
            };       
    }
}

#[derive(Debug)]
struct AuthClient
{
    username: String,
    password: String,
    key: scram_rs::ScramKey,
}

#[async_trait]
impl AsyncScramCbHelper for AuthClient
{
    async 
    fn get_tls_server_endpoint(&self) -> ScramResult<Vec<u8>> 
    {
        scram_rs::HELPER_UNSUP_CLIENT!("endpoint");
    }

    async 
    fn get_tls_unique(&self) -> ScramResult<Vec<u8>> {
        scram_rs::HELPER_UNSUP_CLIENT!("unique");
    }

    async 
    fn get_tls_exporter(&self) -> ScramResult<Vec<u8>> 
    {
        scram_rs::HELPER_UNSUP_CLIENT!("exporter");
    }
}

#[async_trait]
impl AsyncScramAuthClient for AuthClient
{
    async fn get_username(&self) -> &str
    {
        return &self.username;
    }

    async fn get_password(&self) -> &str
    {
        return &self.password;
    }

    async fn get_scram_keys(&self) -> &scram_rs::ScramKey 
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
pub fn main()
{
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async 
        {
            let client = AuthClient::new("user", "password");
    
            let (clie_send, mut serv_recv) = tokio::sync::mpsc::unbounded_channel::<String>();
            let (serv_send, mut clie_recv) = tokio::sync::mpsc::unbounded_channel::<String>();

            let authdb = AuthDB::new();
            let authdbcb = AuthDBCb{};
            let scramtype = ScramCommon::get_scramtype("SCRAM-SHA-256").unwrap();
        
            let server = 
                AsyncScramServer
                    ::<ScramSha256RustNative, AuthDB, AuthDBCb>
                    ::new_variable(BorrowOrConsume::from(authdb), BorrowOrConsume::from(authdbcb), ScramNonce::none(), BorrowOrConsume::from(scramtype.clone())).unwrap();

            let hndl = 
                tokio::spawn(async move 
                    {
                        

                        let mut dyn_server = server.make_dyn();
                    
                        loop
                        {
                            let client_data = serv_recv.recv().await.unwrap();

                            let serv_data = dyn_server.parse_response_base64(client_data.as_bytes()).await;
                            serv_send.send(serv_data.encode_base64()).unwrap();

                            match serv_data
                            {
                                scram_rs::ScramResultServer::Error(e) => 
                                {
                                    println!("server: error: {}", e);
                                    break;
                                },
                                scram_rs::ScramResultServer::Final(_) =>
                                {
                                    println!("server: final!");
                                    break;
                                },
                                _ => {}
                            }
                        }
                    }
                );

            let mut client =
                AsyncScramClient::<ScramSha256RustNative, AuthClient, AuthClient>::new(&client, ScramNonce::None, scram_rs::ChannelBindType::None, &client).unwrap();

            // client sends initial message: cli -> serv
            let ci = client.init_client().await.encode_output_base64().unwrap();
            clie_send.send(ci).unwrap();

            
            loop
            {
                let serv_data = clie_recv.recv().await.unwrap();

                match client.parse_response_base64(serv_data).await
                {
                    Ok(ScramResultClient::Completed) => 
                    {
                        println!("client: completed auth successfully");
                        break;
                    },
                    Ok(out) => clie_send.send(out.encode_output_base64().unwrap()).unwrap(),
                    Err(e) =>
                    {
                        println!("client: error: {}", e);
                        break;
                    }
                }

            }

            hndl.await.unwrap();

            return;
        }
    );

    
}
