use serde::{Deserialize, Serialize};

use crate::node::Node;

pub trait OutLike: Node {}

#[derive(Serialize, Deserialize, Clone, Hash, Eq, PartialEq)]
pub struct OutExitTag(pub String);

pub async fn run_out(node: &impl OutLike) {}
