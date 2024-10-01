use tokio::io::AsyncWriteExt as _;

pub async fn copy_bidirectional(
    a_b: (
        impl tokio::io::AsyncRead + Send + Unpin,
        impl tokio::io::AsyncWrite + Send + Unpin,
    ),
    b_a: (
        impl tokio::io::AsyncRead + Send + Unpin,
        impl tokio::io::AsyncWrite + Send + Unpin,
    ),
) -> Result<(), tokio::io::Error> {
    let (mut a_read, mut b_write) = a_b;
    let (mut b_read, mut a_write) = b_a;

    let a_to_b_task = async {
        tokio::io::copy(&mut a_read, &mut b_write).await?;

        let _ = b_write.shutdown().await;

        tokio::io::Result::Ok(())
    };

    let b_to_a_task = async {
        tokio::io::copy(&mut b_read, &mut a_write).await?;

        let _ = a_write.shutdown().await;

        tokio::io::Result::Ok(())
    };

    tokio::try_join!(a_to_b_task, b_to_a_task)?;

    Ok(())
}
