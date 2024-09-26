mod fake_authority;
mod notes;
mod tproxy_socket;

use std::{
    cell::RefCell,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use fake_authority::FakeAuthority;
use stun::message::Getter as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt};
use webrtc::util::Conn;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let tls = native_tls::TlsConnector::builder().build().unwrap();

    let client = imap::connect(
        (std::env::var("IMAP_SERVER")?, 993),
        std::env::var("IMAP_SERVER")?,
        &tls,
    )
    .unwrap();

    let mut session = client
        .login(std::env::var("IMAP_USER")?, std::env::var("IMAP_PASSWORD")?)
        .map_err(|error| error.0)?;

    // session.run_command("ID (\"name\" \"plug2proxy\")")?;

    // println!("{:?}", String::from_utf8(id_result));

    println!("logged in.");

    // session.create("p2p").unwrap();

    let capabilities = session.capabilities()?;

    println!("{:#?}", capabilities.iter().collect::<Vec<_>>());

    // let mailboxes = session.list(None, Some("*"))?;
    // println!("{:#?}", mailboxes.iter().collect::<Vec<_>>());

    // session.subscribe("p2p")?;

    if false {
        session.append("p2p", "some random content new")?;
    } else {
        let mailbox = session.select("p2p")?;

        println!("{} mails", mailbox.exists);

        let mut idle_handle = session.idle()?;

        idle_handle.set_keepalive(Duration::from_secs(5));

        idle_handle.wait_keepalive()?;

        println!("wait ended");

        let messages = session.fetch("*", "BODY[]")?;

        for message in messages.iter() {
            if let Some(body) = message.body() {
                println!("{:?}", String::from_utf8(body.to_vec())?);
            }
        }
    }

    Ok(())
}
