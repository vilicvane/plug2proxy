use std::{net::SocketAddr, time::Duration};

const PUNCHING_PACKET: &[u8] = &[];

pub async fn punch(socket: &tokio::net::UdpSocket, target: SocketAddr) -> anyhow::Result<()> {
    let send_to_task = async {
        loop {
            println!("sending punching packet...");

            socket.send_to(PUNCHING_PACKET, target).await?;

            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        #[allow(unreachable_code)]
        anyhow::Ok(())
    };

    let receive_task = async {
        socket.recv(&mut []).await?;

        socket.send_to(PUNCHING_PACKET, target).await?;

        anyhow::Ok(())
    };

    let timeout_task = async {
        tokio::time::sleep(Duration::from_secs(10)).await;

        anyhow::bail!("punching timeout");

        #[allow(unreachable_code)]
        anyhow::Ok(())
    };

    tokio::select! {
        _ = send_to_task => {
            panic!("unexpected completion of send_to_task");
        }
        result = receive_task => result,
        result = timeout_task => result,
    }
}
