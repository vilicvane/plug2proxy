use std::{sync::Arc, time::Duration};

pub struct SemaphoreRateLimiter {
    semaphore: Arc<tokio::sync::Semaphore>,
    timeout: Duration,
}

impl SemaphoreRateLimiter {
    pub fn new_arc(permits: usize, timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(permits)),
            timeout,
        })
    }

    pub async fn acquire(&self) -> SemaphoreRateLimiterPermit {
        let timeout = self.timeout;
        let permit = self.semaphore.clone().acquire_owned().await.unwrap();

        SemaphoreRateLimiterPermit::new(permit, timeout)
    }
}

pub type SemaphoreRateLimiterArc = Arc<SemaphoreRateLimiter>;

pub struct SemaphoreRateLimiterPermit {
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
    timeout: Duration,
}

impl SemaphoreRateLimiterPermit {
    pub fn new(permit: tokio::sync::OwnedSemaphorePermit, timeout: Duration) -> Self {
        Self {
            permit: Some(permit),
            timeout,
        }
    }
}

impl Drop for SemaphoreRateLimiterPermit {
    fn drop(&mut self) {
        let permit = self.permit.take().unwrap();
        let timeout = self.timeout;

        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            drop(permit);
        });
    }
}
