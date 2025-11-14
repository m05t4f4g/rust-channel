use crate::config::{PolicyRule, Action};
use crate::inspection::InspectionResult;
use std::net::SocketAddr;
use tracing::debug;  // Add debug macro

#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub action: Action,
    pub rule_name: Option<String>,
    pub reason: String,
}

impl PolicyResult {
    pub fn debug_summary(&self) -> String {
        format!(
            "action: {:?}, rule: {:?}, reason: {}",
            self.action, self.rule_name, self.reason
        )
    }
}

pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
}

impl PolicyEngine {
    pub fn new(rules: Vec<PolicyRule>) -> Self {
        Self { rules }
    }

    pub async fn evaluate(&self, inspection: &InspectionResult, source: &SocketAddr) -> PolicyResult {
        debug!("Evaluating policy for {} with {} rules", source, self.rules.len());

        // Check for explicit deny rules first
        for rule in &self.rules {
            if self.matches_rule(inspection, source, rule) {
                match rule.action {
                    Action::Deny => {
                        debug!("DENY rule matched: {}", rule.name);
                        return PolicyResult {
                            action: Action::Deny,
                            rule_name: Some(rule.name.clone()),
                            reason: "Explicit deny rule matched".to_string(),
                        }
                    }
                    _ => continue,
                }
            }
        }

        // Check for allow rules
        for rule in &self.rules {
            if self.matches_rule(inspection, source, rule) {
                match rule.action {
                    Action::Allow => {
                        debug!("ALLOW rule matched: {}", rule.name);
                        return PolicyResult {
                            action: Action::Allow,
                            rule_name: Some(rule.name.clone()),
                            reason: "Allow rule matched".to_string(),
                        }
                    }
                    Action::RateLimit(limit) => {
                        debug!("RATE_LIMIT rule matched: {} (limit: {})", rule.name, limit);
                        return PolicyResult {
                            action: Action::RateLimit(limit),
                            rule_name: Some(rule.name.clone()),
                            reason: "Rate limit rule matched".to_string(),
                        }
                    }
                    _ => continue,
                }
            }
        }

        // Default deny
        debug!("No rules matched, applying default DENY");
        PolicyResult {
            action: Action::Deny,
            rule_name: None,
            reason: "No matching allow rule found".to_string(),
        }
    }

    fn matches_rule(&self, inspection: &InspectionResult, _source: &SocketAddr, rule: &PolicyRule) -> bool {
        // Check if any of the matched patterns in inspection match our rule
        for matched_pattern in &inspection.matches_patterns {
            if let Some(ref rule_msg_type) = rule.match_pattern.msg_type {
                if matched_pattern == rule_msg_type {
                    return true;
                }
            }
        }

        false
    }

    pub fn reload_rules(&mut self, new_rules: Vec<PolicyRule>) {
        self.rules = new_rules;
    }
    pub fn rules_count(&self) -> usize {
        self.rules.len()
    }
}