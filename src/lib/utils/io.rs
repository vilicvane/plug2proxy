use std::time::Instant;

use tokio::io::AsyncWriteExt as _;

pub async fn copy_bidirectional(
    label: &str,
    a_b: (
        impl tokio::io::AsyncRead + Send + Unpin,
        impl tokio::io::AsyncWrite + Send + Unpin,
        bool,
    ),
    b_a: (
        impl tokio::io::AsyncRead + Send + Unpin,
        impl tokio::io::AsyncWrite + Send + Unpin,
    ),
) -> Result<(), tokio::io::Error> {
    let (mut a_read, mut b_write, a_b_end) = a_b;
    let (mut b_read, mut a_write) = b_a;

    let started_at = Instant::now();

    let mut a_to_b_bytes = 0;
    let mut b_to_a_bytes = 0;

    let a_to_b_task = async {
        if a_b_end {
            let _ = b_write.shutdown().await;
        } else {
            let result = tokio::io::copy(&mut a_read, &mut b_write).await;

            let _ = b_write.shutdown().await;

            a_to_b_bytes = result?;
        }

        tokio::io::Result::Ok(())
    };

    let b_to_a_task = async {
        let result = tokio::io::copy(&mut b_read, &mut a_write).await;

        let _ = a_write.shutdown().await;

        b_to_a_bytes = result?;

        tokio::io::Result::Ok(())
    };

    let result = tokio::try_join!(a_to_b_task, b_to_a_task);

    let elapsed = started_at.elapsed();

    log::debug!("[{label}] copy bidirectional took {elapsed:?}, {a_to_b_bytes} / {b_to_a_bytes}");

    result?;

    Ok(())
}
