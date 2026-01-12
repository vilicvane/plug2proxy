use colored::Colorize;

#[derive(Clone, Copy)]
pub enum ConnectionSide {
  Client,
  Server,
}

impl std::fmt::Display for ConnectionSide {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(
      f,
      "{}",
      match self {
        ConnectionSide::Client => "client".cyan(),
        ConnectionSide::Server => "server".magenta(),
      }
    )
  }
}
