use crate::config::{PolicyRule, Action};
use crate::inspection::InspectionResult;
use std::net::SocketAddr;
use tracing::{debug, info, warn};

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
        debug!("🔍 Evaluating policy for {} with {} rules", source, self.rules.len());
        debug!("📊 Inspection result: is_valid={}, matches_patterns={:?}, violations={:?}",
               inspection.is_valid, inspection.matches_patterns, inspection.violations);

        // Log all available rules for debugging
        for (i, rule) in self.rules.iter().enumerate() {
            debug!("📋 Rule {}: name='{}', action={:?}, msg_type={:?}",
                   i, rule.name, rule.action, rule.match_pattern.msg_type);
        }

        // Check for explicit deny rules first
        for rule in &self.rules {
            if self.matches_rule(inspection, source, rule) {
                match rule.action {
                    Action::Deny => {
                        info!("🚫 DENY rule matched: '{}' for patterns: {:?}", rule.name, inspection.matches_patterns);
                        return PolicyResult {
                            action: Action::Deny,
                            rule_name: Some(rule.name.clone()),
                            reason: format!("Explicit deny rule '{}' matched", rule.name),
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
                        info!("✅ ALLOW rule matched: '{}' for patterns: {:?}", rule.name, inspection.matches_patterns);
                        return PolicyResult {
                            action: Action::Allow,
                            rule_name: Some(rule.name.clone()),
                            reason: format!("Allow rule '{}' matched", rule.name),
                        }
                    }
                    Action::RateLimit(limit) => {
                        info!("⏱️ RATE_LIMIT rule matched: '{}' (limit: {}) for patterns: {:?}", rule.name, limit, inspection.matches_patterns);
                        return PolicyResult {
                            action: Action::RateLimit(limit),
                            rule_name: Some(rule.name.clone()),
                            reason: format!("Rate limit rule '{}' matched", rule.name),
                        }
                    }
                    _ => continue,
                }
            }
        }

        // Default deny with detailed reason
        warn!("❌ No rules matched for patterns: {:?}, applying default DENY", inspection.matches_patterns);
        PolicyResult {
            action: Action::Deny,
            rule_name: None,
            reason: format!("No matching allow rule found for patterns: {:?}", inspection.matches_patterns),
        }
    }

    fn matches_rule(&self, inspection: &InspectionResult, _source: &SocketAddr, rule: &PolicyRule) -> bool {
        debug!("🔎 Checking rule '{}' with msg_type: {:?}", rule.name, rule.match_pattern.msg_type);
        debug!("🔎 Against inspection patterns: {:?}", inspection.matches_patterns);

        // Check if any of the matched patterns in inspection match our rule
        for matched_pattern in &inspection.matches_patterns {
            if let Some(ref rule_msg_type) = rule.match_pattern.msg_type {
                debug!("🔍 Comparing rule pattern '{}' with matched pattern '{}'", rule_msg_type, matched_pattern);
                if matched_pattern == rule_msg_type {
                    debug!("🎯 Pattern MATCH: '{}' == '{}'", matched_pattern, rule_msg_type);
                    return true;
                } else {
                    debug!("❌ Pattern MISMATCH: '{}' != '{}'", matched_pattern, rule_msg_type);
                }
            } else {
                debug!("⚠️ Rule '{}' has no msg_type pattern", rule.name);
            }
        }

        debug!("❌ No patterns matched for rule '{}'", rule.name);
        false
    }

    pub fn reload_rules(&mut self, new_rules: Vec<PolicyRule>) {
        self.rules = new_rules;
    }

    pub fn rules_count(&self) -> usize {
        self.rules.len()
    }

    // Add a method to debug rules
    pub fn debug_rules(&self) {
        info!("📋 Current policy rules ({} total):", self.rules.len());
        for (i, rule) in self.rules.iter().enumerate() {
            info!("  {}. {}: action={:?}, msg_type={:?}",
                  i + 1, rule.name, rule.action, rule.match_pattern.msg_type);
        }
    }
}