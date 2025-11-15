mod engine;
pub use engine::{PolicyEngine, PolicyResult};

// Export config types if needed
pub use crate::config::{PolicyRule, Action};