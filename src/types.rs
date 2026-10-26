use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "INFO" => Severity::Info,
            "LOW" => Severity::Low,
            "MEDIUM" | "MED" => Severity::Medium,
            "HIGH" => Severity::High,
            "CRITICAL" | "CRIT" => Severity::Critical,
            _ => Severity::Low,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub entropy: f64,
    pub modified_epoch_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineManifest {
    pub version: String,
    pub generated_at_epoch: u64,
    pub root_dir: String,
    pub total_files: usize,
    pub total_bytes: u64,
    pub files: HashMap<String, FileMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub path: String,
    pub title: String,
    pub description: String,
    pub previous_hash: Option<String>,
    pub current_hash: Option<String>,
    pub previous_entropy: Option<f64>,
    pub current_entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStats {
    pub total_files_scanned: usize,
    pub total_bytes_scanned: u64,
    pub duration_ms: u64,
    pub clean_files: usize,
    pub modified_files: usize,
    pub added_files: usize,
    pub deleted_files: usize,
    pub ransomware_alerts: usize,
    pub canary_alerts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub tool_version: String,
    pub target_directory: String,
    pub findings: Vec<TamperFinding>,
    pub stats: ScanStats,
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub root_dir: String,
    pub baseline_path: Option<String>,
    pub min_severity: Severity,
    pub json_output_path: Option<String>,
    pub check_canary: bool,
    pub deploy_canary: bool,
    pub entropy_spike_threshold: f64, // e.g. 2.2 jump or final entropy > 7.5
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            root_dir: ".".to_string(),
            baseline_path: None,
            min_severity: Severity::Low,
            json_output_path: None,
            check_canary: true,
            deploy_canary: false,
            entropy_spike_threshold: 2.0,
        }
    }
}
