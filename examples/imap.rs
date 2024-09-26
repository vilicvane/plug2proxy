use std::{
    cell::RefCell,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use clap::Parser as _;
use stun::message::Getter as _;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt};
use webrtc::util::Conn;

#[derive(clap::Parser, Debug)]
struct Cli {
    #[clap(long)]
    append: bool,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

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

    if cli.append {
        let message = lettre::Message::builder()
            .from("vilicvane@live.com".parse()?)
            .to("p2pbridge@aliyun.com".parse()?)
            .subject("p2p")
            .body(format!(
                "some random content new random number {}",
                rand::random::<u32>()
            ))?;

        session.append("p2p", message.formatted())?;

        // session.
    } else {
        let mailbox = if let Ok(mailbox) = session.select("p2p") {
            mailbox
        } else {
            session.create("p2p")?;
            session.select("p2p")?
        };

        loop {
            session.select("p2p")?;

            let seq = session
                .search("NEW")?
                .iter()
                .map(|seq| seq.to_string())
                .collect::<Vec<_>>()
                .join(",");

            println!("seq: {}", seq);

            let entries = session.fetch(seq, "BODY[]")?;

            for entry in entries.iter() {
                println!("{}", String::from_utf8(entry.body().unwrap().to_vec())?);
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        // let mut idle_handle = session.idle()?;

        // idle_handle.set_keepalive(Duration::from_secs(5));

        // idle_handle.wait_keepalive()?;

        // println!("wait ended");

        let messages = session.fetch("*", "BODY[]")?;

        for message in messages.iter() {
            if let Some(body) = message.body() {
                println!("{:?}", String::from_utf8(body.to_vec())?);
            }
        }
    }

    Ok(())
}
