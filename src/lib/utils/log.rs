use std::{env, io::Write};

use colored::Colorize;
use env_logger::Env;
use log::Level;

pub fn init_log() {
    color_backtrace::install();

    env_logger::Builder::from_env(
        Env::default().default_filter_or(format!("{}=info", env!("CARGO_PKG_NAME"))),
    )
    .format(|formatter, record| {
        let timestamp = chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S.%3f")
            .to_string();

        let timestamp = match record.level() {
            Level::Error => timestamp.bright_red(),
            Level::Warn => timestamp.bright_yellow(),
            Level::Info => timestamp.bright_green(),
            Level::Debug => timestamp.bright_black(),
            Level::Trace => timestamp.dimmed(),
        };

        writeln!(formatter, "{} {}", timestamp, record.args())
    })
    .init();
}
