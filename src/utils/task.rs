use tokio::task::JoinSet;

/// Removes completed tasks so a long-lived `JoinSet` does not retain one
/// result allocation for every task it has ever spawned.
pub fn reap_finished_tasks<T: 'static>(join_set: &mut JoinSet<T>, task_name: &str) {
  while let Some(result) = join_set.try_join_next() {
    if let Err(error) = result {
      log::error!("{task_name} failed: {error}");
    }
  }
}
