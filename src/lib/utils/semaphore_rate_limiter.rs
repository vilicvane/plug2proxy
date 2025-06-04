use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub struct SemaphoreRateLimiter {
    semaphore: Arc<Semaphore>,
    initial_permits: usize,
    boostable_permits: usize,
    initial_delay: Duration,
}

impl SemaphoreRateLimiter {
    pub fn new_arc(permits: usize, boostable_permits: usize, initial_delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            semaphore: Arc::new(Semaphore::new(permits)),
            initial_permits: permits,
            boostable_permits,
            initial_delay,
        })
    }

    pub async fn acquire(&self) -> OwnedSemaphorePermit {
        let permit = self.semaphore.clone().acquire_owned().await.unwrap();

        let acquired_at = Instant::now();

        loop {
            let acquired_permits = (self.initial_permits
                - self.semaphore.available_permits()
                - self.boostable_permits)
                .max(0);

            if acquired_permits == 0 {
                break;
            }

            let expected_delay = self.initial_delay * (2u32.pow(acquired_permits as u32));

            if acquired_at + expected_delay < Instant::now() {
                break;
            }

            tokio::time::sleep(self.initial_delay).await;
        }

        permit
    }
}

pub type SemaphoreRateLimiterArc = Arc<SemaphoreRateLimiter>;
