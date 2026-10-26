use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;

use crate::canary::{verify_canary, CanaryStatus, CANARY_FILENAME};
use crate::entropy::is_ransomware_spike;
use crate::hasher::hash_and_measure_file;
use crate::types::*;

pub struct Scanner;

impl Scanner {
    fn is_ignored(path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        path_str.contains(".git")
            || path_str.contains("target")
            || path_str.contains("node_modules")
            || path_str.contains("build")
            || path_str.contains(".vs")
    }

    pub fn generate_baseline(root_dir: &Path) -> io::Result<BaselineManifest> {
        let _start = Instant::now();
        let canonical_root = fs::canonicalize(root_dir)?;
        let mut files = HashMap::new();
        let mut total_bytes = 0u64;

        for entry in WalkDir::new(&canonical_root).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() || Self::is_ignored(path) {
                continue;
            }

            if path.file_name().map(|n| n == CANARY_FILENAME).unwrap_or(false) {
                continue;
            }

            if let Ok(hash_res) = hash_and_measure_file(path) {
                let rel_path = path
                    .strip_prefix(&canonical_root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .replace('\\', "/");

                let modified_epoch = entry
                    .metadata()
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                total_bytes += hash_res.size_bytes;
                files.insert(
                    rel_path.clone(),
                    FileMetadata {
                        relative_path: rel_path,
                        size_bytes: hash_res.size_bytes,
                        sha256: hash_res.sha256,
                        entropy: hash_res.entropy,
                        modified_epoch_secs: modified_epoch,
                    },
                );
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Ok(BaselineManifest {
            version: "1.0.0".to_string(),
            generated_at_epoch: now,
            root_dir: canonical_root.to_string_lossy().to_string(),
            total_files: files.len(),
            total_bytes,
            files,
        })
    }

    pub fn verify_baseline(
        root_dir: &Path,
        baseline: &BaselineManifest,
        config: &ScanConfig,
    ) -> io::Result<ScanReport> {
        let start = Instant::now();
        let canonical_root = fs::canonicalize(root_dir)?;
        let mut findings = Vec::new();
        let mut scanned_files_count = 0usize;
        let mut scanned_bytes = 0u64;
        let mut clean_files = 0usize;
        let mut modified_files = 0usize;
        let mut added_files = 0usize;
        let mut ransomware_alerts = 0usize;
        let mut canary_alerts = 0usize;

        let mut seen_paths = HashSet::new();

        // 1. Check Canary Tripwire if enabled
        if config.check_canary {
            match verify_canary(&canonical_root) {
                CanaryStatus::ModifiedOrEncrypted => {
                    canary_alerts += 1;
                    findings.push(TamperFinding {
                        rule_id: "SW-003".to_string(),
                        severity: Severity::Critical,
                        path: CANARY_FILENAME.to_string(),
                        title: "Critical Canary Decoy Tripwire Triggered (Active Tampering)".to_string(),
                        description: "Anti-ransomware canary decoy file was modified or encrypted."
                            .to_string(),
                        previous_hash: None,
                        current_hash: None,
                        previous_entropy: None,
                        current_entropy: None,
                    });
                }
                CanaryStatus::Deleted => {
                    canary_alerts += 1;
                    findings.push(TamperFinding {
                        rule_id: "SW-003".to_string(),
                        severity: Severity::Critical,
                        path: CANARY_FILENAME.to_string(),
                        title: "Critical Canary Decoy Deleted (Anti-Ransomware Tripwire)".to_string(),
                        description: "Canary decoy file was unexpectedly deleted from directory."
                            .to_string(),
                        previous_hash: None,
                        current_hash: None,
                        previous_entropy: None,
                        current_entropy: None,
                    });
                }
                CanaryStatus::Intact | CanaryStatus::NotInstalled => {}
            }
        }

        // 2. Iterate filesystem and check against baseline
        for entry in WalkDir::new(&canonical_root).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() || Self::is_ignored(path) {
                continue;
            }

            if path.file_name().map(|n| n == CANARY_FILENAME).unwrap_or(false) {
                continue;
            }

            let rel_path = path
                .strip_prefix(&canonical_root)
                .unwrap_or(path)
                .to_string_lossy()
                .replace('\\', "/");

            seen_paths.insert(rel_path.clone());
            scanned_files_count += 1;

            if let Ok(current_meta) = hash_and_measure_file(path) {
                scanned_bytes += current_meta.size_bytes;

                if let Some(expected_meta) = baseline.files.get(&rel_path) {
                    if current_meta.sha256 != expected_meta.sha256 {
                        modified_files += 1;

                        // Check for sudden entropy spike (Ransomware encryption signature)
                        if is_ransomware_spike(expected_meta.entropy, current_meta.entropy) {
                            ransomware_alerts += 1;
                            findings.push(TamperFinding {
                                rule_id: "SW-001".to_string(),
                                severity: Severity::Critical,
                                path: rel_path.clone(),
                                title: "Ransomware Encryption Spike Detected".to_string(),
                                description: format!(
                                    "File entropy spiked from structured ({:.2}) to ciphertext ({:.2}) alongside hash mismatch.",
                                    expected_meta.entropy, current_meta.entropy
                                ),
                                previous_hash: Some(expected_meta.sha256.clone()),
                                current_hash: Some(current_meta.sha256),
                                previous_entropy: Some(expected_meta.entropy),
                                current_entropy: Some(current_meta.entropy),
                            });
                        } else {
                            // Standard modification / tamper
                            findings.push(TamperFinding {
                                rule_id: "SW-002".to_string(),
                                severity: Severity::High,
                                path: rel_path.clone(),
                                title: "File Modified / Cryptographic Hash Mismatch".to_string(),
                                description: format!(
                                    "File digest differs from baseline ({:.2} -> {:.2} bits entropy).",
                                    expected_meta.entropy, current_meta.entropy
                                ),
                                previous_hash: Some(expected_meta.sha256.clone()),
                                current_hash: Some(current_meta.sha256),
                                previous_entropy: Some(expected_meta.entropy),
                                current_entropy: Some(current_meta.entropy),
                            });
                        }
                    } else {
                        clean_files += 1;
                    }
                } else {
                    // New file added
                    added_files += 1;
                    findings.push(TamperFinding {
                        rule_id: "SW-004".to_string(),
                        severity: Severity::Medium,
                        path: rel_path.clone(),
                        title: "Untracked / Injected File Detected".to_string(),
                        description: "File was created or placed into protected directory after baseline generation."
                            .to_string(),
                        previous_hash: None,
                        current_hash: Some(current_meta.sha256),
                        previous_entropy: None,
                        current_entropy: Some(current_meta.entropy),
                    });
                }
            }
        }

        // 3. Check for deleted files (present in baseline but missing on disk)
        let mut deleted_files = 0usize;
        for (expected_path, meta) in &baseline.files {
            if !seen_paths.contains(expected_path) {
                deleted_files += 1;
                findings.push(TamperFinding {
                    rule_id: "SW-005".to_string(),
                    severity: Severity::Medium,
                    path: expected_path.clone(),
                    title: "Tracked File Deleted from Target".to_string(),
                    description: "File documented in baseline manifest is missing on disk."
                        .to_string(),
                    previous_hash: Some(meta.sha256.clone()),
                    current_hash: None,
                    previous_entropy: Some(meta.entropy),
                    current_entropy: None,
                });
            }
        }

        // Filter findings by min_severity
        findings.retain(|f| f.severity >= config.min_severity);

        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ScanReport {
            tool_version: "1.0.0".to_string(),
            target_directory: canonical_root.to_string_lossy().to_string(),
            findings,
            stats: ScanStats {
                total_files_scanned: scanned_files_count,
                total_bytes_scanned: scanned_bytes,
                duration_ms,
                clean_files,
                modified_files,
                added_files,
                deleted_files,
                ransomware_alerts,
                canary_alerts,
            },
        })
    }
}
