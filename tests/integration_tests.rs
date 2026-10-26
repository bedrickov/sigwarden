use sigwarden_core::*;
use std::fs;

#[test]
fn test_entropy_properties() {
    let zeros = vec![0u8; 1024];
    assert_eq!(calculate_entropy(&zeros), 0.0);

    let mut uniform = Vec::with_capacity(256 * 10);
    for i in 0..2560 {
        uniform.push((i % 256) as u8);
    }
    let max_ent = calculate_entropy(&uniform);
    assert!((max_ent - 8.0).abs() < 0.001);

    let text = b"The quick brown fox jumps over the lazy dog. Production systems engineering.";
    let text_ent = calculate_entropy(text);
    assert!(text_ent > 3.0 && text_ent < 5.0);
    assert_eq!(classify_entropy(text_ent), EntropyClass::StructuredText);
}

#[test]
fn test_ransomware_spike_detection() {
    // Low entropy text file (3.8) -> jumps to encrypted payload (7.8)
    assert!(is_ransomware_spike(3.8, 7.8));
    // High entropy already (7.2 -> 7.4) is NOT a spike
    assert!(!is_ransomware_spike(7.2, 7.4));
    // Small change
    assert!(!is_ransomware_spike(4.0, 4.5));
}

#[test]
fn test_canary_tripwire_lifecycle() {
    let test_dir = std::env::temp_dir().join("sigwarden_canary_test");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();

    // 1. Initial state: NotInstalled
    assert_eq!(verify_canary(&test_dir), CanaryStatus::NotInstalled);

    // 2. Deploy
    let canary_path = deploy_canary(&test_dir).unwrap();
    assert!(canary_path.exists());
    assert_eq!(verify_canary(&test_dir), CanaryStatus::Intact);

    // 3. Tamper / Encrypt
    fs::write(&canary_path, b"ENCRYPTED_RANSOMWARE_PAYLOAD_LOCKED").unwrap();
    assert_eq!(verify_canary(&test_dir), CanaryStatus::ModifiedOrEncrypted);

    // 4. Remove file -> NotInstalled
    fs::remove_file(&canary_path).unwrap();
    assert_eq!(verify_canary(&test_dir), CanaryStatus::NotInstalled);

    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_baseline_and_tamper_detection() {
    let test_dir = std::env::temp_dir().join("sigwarden_audit_test");
    let _ = fs::remove_dir_all(&test_dir);
    fs::create_dir_all(&test_dir).unwrap();

    let file_a = test_dir.join("config.toml");
    let file_b = test_dir.join("main.rs");
    fs::write(&file_a, b"server_port = 8080\napi_key = \"secret123\"\n").unwrap();
    fs::write(&file_b, b"fn main() { println!(\"Hello\"); }\n").unwrap();

    // Generate baseline
    let baseline = Scanner::generate_baseline(&test_dir).unwrap();
    assert_eq!(baseline.total_files, 2);

    let config = ScanConfig::default();

    // Initial verify: should be 100% clean
    let report_initial = Scanner::verify_baseline(&test_dir, &baseline, &config).unwrap();
    assert_eq!(report_initial.stats.clean_files, 2);
    assert_eq!(report_initial.findings.len(), 0);

    // Modify file_a
    fs::write(&file_a, b"server_port = 9090\nTAMPERED = true\n").unwrap();

    let report_tampered = Scanner::verify_baseline(&test_dir, &baseline, &config).unwrap();
    assert_eq!(report_tampered.stats.modified_files, 1);
    assert_eq!(report_tampered.findings.len(), 1);
    assert_eq!(report_tampered.findings[0].rule_id, "SW-002");

    let _ = fs::remove_dir_all(&test_dir);
}
