use tokio::io::AsyncWriteExt as _;

pub async fn copy_bidirectional(
    a: (
        impl tokio::io::AsyncRead + Send + Unpin,
        impl tokio::io::AsyncWrite + Send + Unpin,
    ),
    b: (
        impl tokio::io::AsyncRead + Send + Unpin,
        impl tokio::io::AsyncWrite + Send + Unpin,
    ),
) -> Result<(), tokio::io::Error> {
    let (mut a_read, mut a_write) = a;
    let (mut b_read, mut b_write) = b;

    let a_to_b_task = async {
        tokio::io::copy(&mut a_read, &mut b_write).await?;

        b_write.shutdown().await?;

        tokio::io::Result::Ok(())
    };

    let b_to_a_task = async {
        tokio::io::copy(&mut b_read, &mut a_write).await?;

        a_write.shutdown().await?;

        tokio::io::Result::Ok(())
    };

    tokio::try_join!(a_to_b_task, b_to_a_task)?;

    Ok(())
}
