# musl toolchains https://musl.cc/
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="aarch64-linux-musl-gcc"

cargo build --release
cargo build --release --target aarch64-unknown-linux-musl
