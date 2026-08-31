//! Devin CLI connector.
//!
//! Detects the Cognition Devin CLI. Session/conversation scanning is not
//! supported yet; this connector reports installation status and storage roots.

use super::{Connector, franken_detection_for_connector};
use crate::types::{DetectionResult, NormalizedConversation};

pub struct DevinConnector;

impl Default for DevinConnector {
    fn default() -> Self {
        Self::new()
    }
}

impl DevinConnector {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Connector for DevinConnector {
    fn detect(&self) -> DetectionResult {
        franken_detection_for_connector("devin").unwrap_or_else(DetectionResult::not_found)
    }

    fn scan(
        &self,
        _ctx: &super::scan::ScanContext,
    ) -> anyhow::Result<Vec<NormalizedConversation>> {
        Ok(Vec::new())
    }
}
