use std::{sync::Arc, time::Duration};

#[derive(Clone, derive_more::From, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum OneOrMany<T> {
    One(T),
    Many(Vec<T>),
}

impl<T> OneOrMany<T> {
    pub fn into_vec(self) -> Vec<T> {
        match self {
            OneOrMany::One(t) => vec![t],
            OneOrMany::Many(v) => v,
        }
    }
}

pub fn keep_arc_for_duration<T>(value: Arc<T>, duration: Duration)
where
    T: Sync + Send + 'static,
{
    tokio::spawn(async move {
        tokio::time::sleep(duration).await;

        drop(value);
    });
}
