use itertools::Itertools;

use super::TunnelId;

pub fn get_tunnel_string(r#type: &'static str, id: TunnelId, labels: &[String]) -> String {
    let id_short = &id.0.as_bytes()[..4]
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .join("");

    let name = format!("{} {id_short}", r#type);

    if labels.is_empty() {
        name
    } else {
        format!("{} ({})", name, labels.join(","))
    }
}
