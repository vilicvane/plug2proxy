use std::net::SocketAddr;

pub fn get_destination_string(address: SocketAddr, name: &Option<String>) -> String {
    format!(
        "{}{}",
        address,
        name.as_ref()
            .map_or_else(|| "".to_owned(), |name| format!(" ({})", name))
    )
}
